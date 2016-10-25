{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveGeneric #-}

module Main where

import Web.Scotty
import Web.Scotty.TLS
import U2F
import U2F.Types
import System.Random
import Data.Text.Lazy.Encoding (decodeUtf8)
import Web.Scotty.Internal.Types (ActionT)
import Data.Aeson (encode, decode)
import Data.Either.Unwrap (fromRight)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as E
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.IORef
import System.IO.Unsafe
import Control.Monad.IO.Class
import Data.Maybe
import qualified Control.Monad.State as ST
import System.Random (StdGen, mkStdGen, random)
import GHC.Generics
import Data.Aeson ((.:), (.:?), decode, FromJSON(..),
  ToJSON(..), Value(..), genericParseJSON, genericToJSON,  defaultOptions)
import qualified Data.Binary as DB
import qualified Data.List as DL

data UserRegistration = UserRegistration {
  username :: String,
  password :: String,
  registration :: Registration
} deriving (Show, Generic)
instance FromJSON UserRegistration
instance ToJSON UserRegistration

data UserSignin = UserSignin {
  user :: String,
  pass :: String,
  signin :: Signin
} deriving (Show, Generic)
instance FromJSON UserSignin

data SavedRegistration = SavedRegistration {
  request :: Request,
  savedKeyHandle :: BS.ByteString,
  identifier :: Maybe String
} deriving (Show, Generic)

data Identifier = Identifier {
  ident :: String
} deriving (Show, Generic)
instance ToJSON Identifier

-- | RequestCache, an in-memory list of outstanding requests.
requestCache :: [Request]
requestCache = []

-- | SavedRegistrationList, in-memory list of keys successfully registered
registeredKeyList :: [SavedRegistration]
registeredKeyList = []

-- | Not actually a good random thing generator.
--   Good enough for demo app purposes.
randomChallenge:: IO (T.Text)
randomChallenge = do
  randInt <- randomIO :: IO (Double)
  return $ formatOutputBase64 $ LBS.toStrict $ DB.encode randInt

-- findRegistration
findRequestByChallenge :: [Request] -> T.Text -> Either U2FError Request
findRequestByChallenge requestList chall = case (foundRequest) of
      Just request -> Right request
      Nothing -> Left ChallengeMismatchError
    where foundRequest = DL.find (\x -> challenge x == chall) requestList

findRegistrationByIdentifier :: [SavedRegistration] -> String -> Either U2FError SavedRegistration
findRegistrationByIdentifier requestList ident = case (foundRequest) of
      Just request -> Right request
      Nothing -> Left SigninParseError
    where foundRequest = DL.find (\x -> (identifier x) == Just ident) requestList

parseUserRegistration :: LBS.ByteString -> Either U2FError UserRegistration
parseUserRegistration x = case (Data.Aeson.decode  x :: Maybe UserRegistration) of
  Just response -> Right response
  Nothing -> Left RegistrationParseError

parseUserSignin :: LBS.ByteString -> Either U2FError UserSignin
parseUserSignin x = case (Data.Aeson.decode  x :: Maybe UserSignin) of
  Just response -> Right response
  Nothing -> Left ChallengeMismatchError

routes rCache rSaved = do
  -- Static stuff routes
  get "/" $ file "static/example.html"
  get "/single" $ file "static/single-auth-example.html"
  get "/u2f-api.js" $ file "static/js/u2f-api.js"
  get "/jquery-2.2.4.min.js" $ file "static/js/jquery-2.2.4.min.js"
  get "/bootstrap.min.css" $ file "static/bootstrap.min.css"
  -- U2F Routes
  -- =========
  -- | Request endpoint, spits out a new request with (mostlyyyy) random challenge, saves request to our list
  get "/request" $ do
    chall <- liftIO $ randomChallenge
    request <- pure $ Request (T.pack "https://localhost:4000") (T.pack "U2F_V2") chall Nothing
    written <- liftIO $ modifyIORef rCache (++ [request])
    json $ request
  -- | Endpoints for username-based registration
  post "/user-register" $ do
    registerJSON <- body
    requests <- liftIO $ readIORef rCache
    possibleRegistration <- return $ do
      userRegistration <- parseUserRegistration registerJSON
      registration <- pure $ registration userRegistration
      request <- findRequestByChallenge requests (registration_challenge $ registration)
      verifiedReg <- verifyRegistration request registration
      registrationData <- parseRegistrationData $ TE.encodeUtf8 $ registration_registrationData registration
      return (verifiedReg, (registrationData_publicKey registrationData), (username userRegistration) ++ (password userRegistration))
    case (possibleRegistration) of
      Right (r, pkey, identifier) -> do
        liftIO $ modifyIORef rSaved (++ [SavedRegistration r  pkey (Just identifier)])
        json r
      Left err -> do
        raise $ TL.pack (show err)
  post "/user-signin" $ do
    signinJSON <- body
    requests <- liftIO $ readIORef rCache
    registrations <- liftIO $ readIORef rSaved
    possibleSignin <- return $ do
      userSignin <- parseUserSignin signinJSON
      signin <- pure $ signin userSignin
      currentRequest <- findRequestByChallenge requests (clientData_challenge $ fromRight $ parseClientData $ TE.encodeUtf8 $ signin_clientData signin)
      originalRequest <- findRegistrationByIdentifier registrations ((user userSignin) ++ (pass userSignin))
      return $ verifySignin (savedKeyHandle originalRequest) currentRequest signin
    case (possibleSignin) of
      Right _ -> json $ TL.pack "{status: 'ok'}"
      Left err -> raise $ TL.pack (show err)
  -- | Endpoints for username-based registration
  post "/single-register" $ do
    registerJSON <- body
    requests <- liftIO $ readIORef rCache
    possibleRegistration <- return $ do
      registration <- parseRegistration $ LBS.unpack $ registerJSON
      request <- findRequestByChallenge requests (registration_challenge $ registration)
      verifiedReg <- verifyRegistration request registration
      registrationData <- parseRegistrationData $ TE.encodeUtf8 $ registration_registrationData registration
      return (verifiedReg, (registrationData_publicKey registrationData), (T.unpack $ formatOutputBase64 $ registrationData_certificate registrationData))
    case (possibleRegistration) of
      Right (r, pkey, identifier) -> do
        liftIO $ modifyIORef rSaved (++ [SavedRegistration r pkey (Just identifier)])
        json $ Identifier $ identifier
      Left err -> do
        raise $ TL.pack (show err)
  post "/single-signin" $ do
    signinJSON <- body
    requests <- liftIO $ readIORef rCache
    registrations <- liftIO $ readIORef rSaved
    possibleSignin <- return $ do
      userSignin <- parseUserSignin signinJSON
      signin <- pure $ signin userSignin
      currentRequest <- findRequestByChallenge requests (clientData_challenge $ fromRight $ parseClientData $ TE.encodeUtf8 $ signin_clientData signin)
      originalRequest <- findRegistrationByIdentifier registrations ((user userSignin) ++ (pass userSignin))
      return $ verifySignin (savedKeyHandle originalRequest) currentRequest signin
    case (possibleSignin) of
      Right _ -> json $ TL.pack "{status: 'ok'}"
      Left err -> raise $ TL.pack (show err)
  get "/debug" $ do
    requests <- liftIO $ readIORef rSaved
    text $ TL.pack (show requests)
  -- | Route for retrieving keyhandles
  get "/keyhandle" $ do
    identifier <- param "identifier"
    registrations <- liftIO $ readIORef rSaved
    case (findRegistrationByIdentifier registrations identifier) of
      Right reg -> json $ TL.fromStrict (fromJust $ keyHandle $ Main.request reg)
      Left _ -> raise "NoKeyHandle"

main :: IO ()
main = do
  requests <- newIORef $ requestCache
  registered <- newIORef $ registeredKeyList
  scottyTLS 4000 "server.key" "server.crt" (routes requests registered)
