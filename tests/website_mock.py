from tests.async_mock import AsyncMock

_AUTH_RESPONSE = '''{
    "platformType": "uplay",
    "ticket": "LongTicket",
    "twoFactorAuthenticationTicket": None,
    "profileId": "12345",
    "userId": "Mock",
    "nameOnPlatform": "KptMock",
    "environment": "Prod",
    "expiration": "2019-03-05T11:28:49.0783145Z",
    "spaceId": "1234",
    "clientIp": "420.BL.4ZE.IT",
    "clientIpCountry": "US",
    "serverTime": "2019-03-05T08:28:49.0792996Z",
    "sessionId": "Session_id",
    "sessionKey": "Session_key",
    "rememberMeTicket": "Rememeber_me"
}'''


class BackendClientMock(AsyncMock):
    def authorize(self, auth_code):
        pass

    def set_auth_lost_callback(self, callback):
        pass

    def is_authenticated(self):
        return True

    async def authorise_with_stored_credentials(self, credentials):
        return await self.get_user_data()

    async def authorise_with_cookies(self, credentials):
        return {'userId': '123', 'username': 'Mock'}

    def restore_credentials(self, data):
        pass

    async def get_user_data(self):
        return {'userId': '123', 'username': 'Mock', 'nameOnPlatform': 'MockPl', 'accountIssues': None,
                'communicationOptIn': True, 'communicationThirdPartyOptIn': False, 'country': 'US',
                'dateCreated': '2017-11-06T17:57:05.9770000Z', 'dateOfBirth': '1990-01-01T00:00:00.0000000Z',
                'email': 'mocker@gmail.com', 'firstName': None, 'gender': None, 'hasAcceptedLegalOptins': True,
                'lastName': None, 'preferredLanguage': 'en',
                'status': {'autoGeneratedUsername': False, 'dateOfBirthApproximated': False, 'invalidEmail': False,
                           'missingRequiredInformation': False, 'pendingDeactivation': False,
                           'recoveringPassword': False, 'passwordUpdateRequired': False, 'reserved': False,
                           'changeEmailPending': False, 'inactiveAccount': False, 'generalStatus': 'activated',
                           'suspiciousActivity': False, 'locked': False}, 'accountType': 'Ubisoft'}

    async def get_game_stats(self, space_id):
        return {'Statscards': []}

    async def get_friends(self):
        return {'friends': [{'pid': '420', 'nameOnPlatform': 'mocker1', 'lastModified': '2018-12-27T00:00:00.0000000',
                             'state': 'Friends'},
                            {'pid': '123', 'nameOnPlatform': 'mocker2', 'lastModified': '2019-03-29T00:00:00.0000000',
                             'state': 'Friends'},
                            {'pid': '321', 'nameOnPlatform': 'mocker3', 'lastModified': '2019-05-14T00:00:00.0000000',
                             'state': 'Friends'}]}

    async def get_subscription_titles(self):
        return None

    async def get_entitlements(self):
        return {
            "entitlements": [
              {
                "productId": 4,
                "availability": "playable",
                "accessLevel": "owned",
                "source": "activation",
                "type": "game",
                "spaceId": "97ef669a-c028-4c25-b5ff-7335aa5d806c",
                "applicationId": "20a72d33-4b3e-47df-b88c-bbd632ed57df",
                "playable": True,
                "downloadable": True,
                "protectedTimeTrial": False,
                "grantedAt": "2020-05-01T10:55:31.000Z",
                "playTrial": None
              },
              {
                "productId": 46,
                "availability": "playable",
                "accessLevel": "owned",
                "source": "activation",
                "type": "game",
                "spaceId": "50228b8c-bbaa-4c32-83c6-2831a1ac317c",
                "applicationId": "15a42aaf-f5cc-47df-bbb3-f59768ac6eed",
                "playable": True,
                "downloadable": True,
                "protectedTimeTrial": False,
                "grantedAt": "2021-09-08T13:01:27.000Z",
                "playTrial": None
              },
            ]
        }

    def get_applications(self):
        pass

    async def get_subscription(self):
        pass
