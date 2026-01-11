import json

from src.stats import find_times, _normalize_last_played


DEFAULT = None


class StatCardMock(object):
    def __init__(self, name, display_name, time_format=False, value=None, unit='Seconds', last_modified=None):
        self.name = name
        self.display_name = display_name
        self.format = 'LongTimespan' if time_format else 'sthElse'
        self.value = str(value)
        self.unit = unit
        self.last_modified = last_modified

    def as_dict(self):
        return {
            'statName': self.name,
            'displayName': self.display_name,
            'format': self.format,
            'value': self.value,
            'unit': self.unit,
            'lastModified': self.last_modified
        }

def test_no_candidate():
    cards = [
        StatCardMock('StatName1', 'DisplayName mock').as_dict(),
        StatCardMock('StatName2', 'DisplayName mock').as_dict()
    ]
    assert [find_times(statscards=card) for card in cards] == (DEFAULT, DEFAULT)


def test_playtime_one_timestamp():
    timeplayed = str(60*300)
    cards = [
        StatCardMock('StatName1', 'DisplayName mock').as_dict(),
        StatCardMock('StatName2', 'This should be catched', True, timeplayed).as_dict(),
    ]
    assert [find_times(statscards=card) for card in cards] == (300, DEFAULT)


def test_playtime_one_zero():
    timeplayed = '0'
    cards = [
        StatCardMock('StatName2', 'This should be catched', True, timeplayed, unit="Seconds").as_dict(),
    ]
    assert [find_times(statscards=card) for card in cards] == (int(timeplayed), DEFAULT)


def test_playtime_one_timestamp_round():
    """should round down to full minutes played"""
    timeplayed_sec = '91'
    timeplayed_min = 1
    cards = [
        StatCardMock('StatName1', 'DisplayName mock').as_dict(),
        StatCardMock('StatName2', 'This should be catched', True, timeplayed_sec).as_dict(),
    ]
    assert [find_times(statscards=card) for card in cards] == (timeplayed_min, DEFAULT)


def test_playtime_good_name():
    good_name = 'Playtime'
    t = 30
    cards = [
        StatCardMock('StatName1', 'sdfafasf', True, 60*10).as_dict(),
        StatCardMock('TTPTotal', good_name, True, 60*t).as_dict(),
    ]
    assert [find_times(statscards=card) for card in cards] == (t, DEFAULT)


def test_playtime_assasin_collection():
    t1 = '120'  # 2min
    t2 = '65'   # ~1min
    t3 = 'None'
    total_min = 3
    cards = [
        StatCardMock('storyCompletion.gameplayed.AC2', 'ACII | Story (%)', False, '23').as_dict(),
        StatCardMock('timePlayed.gameplayed.AC2', 'ACII | Play Time', True, t1, 'Seconds').as_dict(),
        StatCardMock('totalSync.gameplayed.ACB', 'ACB | Total Synchronization (%)').as_dict(),
        StatCardMock('storyCompletion.gameplayed.ACB', 'ACB | Story (%)').as_dict(),
        StatCardMock('timePlayed.gameplayed.ACB', 'ACB | Play Time', True, t2, 'Seconds').as_dict(),
        StatCardMock('totalSync.gameplayed.ACR', 'ACR | Total Synchronization (%)').as_dict(),
        StatCardMock('storyCompletion.gameplayed.ACR', 'ACR | Story (%)').as_dict(),
        StatCardMock('timePlayed.gameplayed.ACR', 'ACR | Play Time', True, t3, 'None').as_dict()
    ]
    assert [find_times(statscards=card) for card in cards] == (total_min, DEFAULT)


def test_playtime_assasin3_remastered():
    t1 = '0'
    t2 = 'None'
    total_min = 0
    cards = [
        StatCardMock('timePlayed.gameplayed.AC3', 'AC3 | Play Time', True, t1, 'Seconds').as_dict(),
        StatCardMock('totalSync.gameplayed.AC3', 'AC3 | Total Synchronization (%)').as_dict(),
        StatCardMock('timePlayed.gameplayed.ACL', 'ACL | Play Time', True, t2, 'Seconds').as_dict(),
        StatCardMock('totalSync.gameplayed.ACL', 'ACL | Total Synchronization (%)').as_dict(),
    ]
    assert [find_times(statscards=card) for card in cards] == (total_min, DEFAULT)


def test_two_modes():
    t1 = 24342
    t2 = 1231
    total = round((t1 + t2) / 60)
    cards = [
        StatCardMock('TTPPVE', 'PvE Play time', True, t1).as_dict(),
        StatCardMock('TTPPVP', 'PvP Play time', True, t2).as_dict(),
        StatCardMock('storyCompletion.gameplayed.ACR', 'ACR | Story (%)').as_dict(),
    ]
    assert [find_times(statscards=card) for card in cards] == (total, DEFAULT)


def test_lastplayed_from_iso():
    iso = '2019-03-21T12:01:19.636Z'
    timestamp_rounded = 1553169680
    assert _normalize_last_played({'lastModified': iso}) == timestamp_rounded


def test_lastplayed_from_iso_2():
    iso = '2017-09-29T22:14:00.000Z'
    timestamp_rounded = 1506723240
    assert _normalize_last_played({'lastModified': iso}) == timestamp_rounded


def test_lastplayed_from_iso_3():
    iso = '1970-01-01T00:01:00Z'
    timestamp_rounded = 60
    assert _normalize_last_played({'lastModified': iso}) == timestamp_rounded


def test_lastplayed_from_iso_none():
    assert _normalize_last_played({'lastModified': None}) == None


def test_gametimes_two_modes_with_last_times_hours():
    """Two modes with time in Minutes"""
    t1 = 2434
    t2 = 123
    total = round(t1 + t2)
    older_modify_time = '2018-12-29T22:14:00.021Z'
    newer_modify_time = '2019-03-29T22:14:20.200Z'
    newer_modify_timestamp = 1553897660
    cards = [
        StatCardMock('TTPSolo', 'Play time being alone', True, t1, 'Minutes', older_modify_time).as_dict(),
        StatCardMock('TTPCoop', 'Coop Play time', True, t2, 'Minutes', newer_modify_time).as_dict(),
        StatCardMock('storyCompletion.gameplayed.ACR', 'ACR | Story (%)').as_dict(),
    ]
    assert [find_times(statscards=card) for card in cards] == (total, newer_modify_timestamp)


def test_default_values_when_not_played():
    """One card of type LongTimespan; "" and 1970 are Uplay defaults when game was not played"""
    json_stat = '''{
        "statName": "TotalPlayTime",
        "displayName": "Play time",
        "locale": "en-US",
        "value": "",
        "obj": "",
        "ordinal": 3,
        "format": "LongTimespan",
        "unit": "Seconds",
        "semantic": "Cumulative",
        "sort": "Descending",
        "startDate": null,
        "endDate": null,
        "lastModified": "1970-01-01T00:00:00.000Z"
    }'''
    cards = [
        json.loads(json_stat)
    ]
    assert [find_times(statscards=card) for card in cards] == (0, 0)


def test_gametimes_champions_of_anteria():
    """Buggy uplay game stats. 'Hours' in this case should be treated as 'Miliseconds'"""
    playtime_min = 1
    playtime_ms = 1000 * 60 * playtime_min
    space_id = '4b20d5ee-461e-4d27-8c56-e258577c5ed3'
    json_stat = f'''{{
        "statName": "TotalDuration",
        "displayName": "Playtime",
        "locale": "en-US",
        "value": "{playtime_ms}",
        "obj": "",
        "ordinal": 0,
        "format": "LongTimespan",
        "unit": "Hours",
        "semantic": "Cumulative",
        "sort": "Descending",
        "startDate": "2016-08-01T09:30:00.000Z",
        "endDate": null,
        "lastModified": "2017-04-20T22:20:05.150Z"
    }}'''
    cards = [
        json.loads(json_stat)
    ]
    assert [find_times(statscards=card) for card in cards] == (playtime_min, 1492726805)


def only_last_played():
    last_modified = '2019-03-21T12:01:19.636Z'
    last_modified_timestamp = 1553169680
    cards = [
        {'displayName': 'Number of Maps Published', 'endDate': None, 'format': 'Integer', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 13, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-22T23:31:00.000Z', 'statName': 'AMapsPublished', 'unit': '', 'value': '0'},
        {'displayName': 'Number of Wins in Arcade PVP', 'endDate': None, 'format': 'Integer', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 16, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-02-03T00:39:00.000Z', 'statName': 'APvPWins', 'unit': '', 'value': '0'},
        {'displayName': 'Number of Deaths in...rcade PVP', 'endDate': None, 'format': 'Integer', 'lastModified': last_modified, 'locale': 'en-GB', 'obj': '', 'ordinal': 9, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-22T23:51:00.000Z', 'statName': 'DDeathArcadePvP', 'unit': '', 'value': '0'},
    ]
    assert [find_times(statscards=card) for card in cards] == (DEFAULT, last_modified_timestamp)


def test_gametimes_farcry5():
    time_played_in_campain_mode = '280'
    time_played_in_arcade_mode = '20'
    total_playtime_sec = '300'
    total_playtime_min = 5
    last_modified = '2019-03-21T12:01:19.636Z'
    last_modified_timestamp = 1553169680
    cards = [
        {'displayName': 'Number of All Takedown Kills', 'endDate': None, 'format': 'Integer', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 11, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-22T23:58:00.000Z', 'statName': 'KTKDAll', 'unit': '', 'value': '0'},
        {'displayName': 'Number of Fish Caught', 'endDate': None, 'format': 'Integer', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 6, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-22T23:59:00.000Z', 'statName': 'OWFishing', 'unit': '', 'value': '0'},
        {'displayName': 'Number of Hostages Rescued', 'endDate': None, 'format': 'Integer', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 5, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-23T00:00:00.000Z', 'statName': 'OWHostage', 'unit': '', 'value': '0'},
        {'displayName': 'Outposts Captured', 'endDate': None, 'format': 'Integer', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 3, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-23T00:01:00.000Z', 'statName': 'OWOutpost', 'unit': '', 'value': '0'},
        {'displayName': 'Time Played in Arcade mode', 'endDate': None, 'format': 'LongTimespan', 'lastModified': '2019-03-21T12:01:19.637Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 7, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-23T00:03:00.000Z', 'statName': 'TTPArcade', 'unit': 'Seconds', 'value': time_played_in_arcade_mode},
        {'displayName': 'Time Played in campaign mode', 'endDate': None, 'format': 'LongTimespan', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 1, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-23T00:04:00.000Z', 'statName': 'TTPCampaign', 'unit': 'Seconds', 'value': time_played_in_campain_mode},
        {'displayName': 'Time Played in all game modes', 'endDate': None, 'format': 'LongTimespan', 'lastModified': last_modified, 'locale': 'en-GB', 'obj': '', 'ordinal': 0, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-23T00:05:00.000Z', 'statName': 'TTPGameplay', 'unit': 'Seconds', 'value': total_playtime_sec},
        {'displayName': 'Time Spent in Arcade Editor', 'endDate': None, 'format': 'LongTimespan', 'lastModified': '2019-03-21T12:01:19.636Z', 'locale': 'en-GB', 'obj': '', 'ordinal': 12, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2018-01-23T00:07:00.000Z', 'statName': 'TTPIGE', 'unit': 'Seconds', 'value': '0'},
        {'displayName': 'Arcade Player Level', 'endDate': None, 'format': 'Integer', 'lastModified': '1970-01-01T00:00:00.000Z', 'locale': 'en-GB', 'obj': None, 'ordinal': 14, 'semantic': 'Cumulative', 'sort': 'Descending', 'startDate': '2017-09-29T22:14:00.000Z', 'statName': 'ArcadePlayerLevel', 'unit': '', 'value': None},
    ]
    assert [find_times(statscards=card) for card in cards] == (total_playtime_min, last_modified_timestamp)


def test_gamestime_trackmania():
    total_playtime_sec = '2290500'
    total_playtime_min = 38175
    cards = [
        {'statName': 'ubiplusPlaytime', 'displayName': 'Total play time in ubiplus', 'value': '146203', 'format': 'LongTimespan', 'unit': 'Seconds', 'startDate': '2020-06-27T00:23:00.131Z', 'endDate': None, 'lastModified': '2021-05-30T13:19:26.788Z'},
        {'statName': 'CreatePlaytime', 'displayName': 'Total play time in Create', 'value': '145648', 'format': 'LongTimespan', 'unit': 'Seconds', 'startDate': '2020-06-27T00:25:00.685Z', 'endDate': None, 'lastModified': '2021-05-24T17:18:13.616Z'},
        {'statName': 'LivePlaytime', 'displayName': 'Total play time in Live', 'value': '1498309', 'format': 'LongTimespan', 'unit': 'Seconds', 'startDate': '2020-06-27T00:19:00.358Z', 'endDate': None, 'lastModified': '2021-05-31T22:00:01.376Z'}, 
        {'statName': 'LocalPlaytime', 'displayName': 'Total play time in Local', 'value': '2875', 'format': 'LongTimespan', 'unit': 'Seconds', 'startDate': '2020-06-27T00:24:00.522Z', 'endDate': None, 'lastModified': '2020-10-29T19:44:50.242Z'}, 
        {'statName': 'SoloPlaytime', 'displayName': 'Total play time in Solo', 'value': '489734', 'format': 'LongTimespan', 'unit': 'Seconds', 'startDate': '2020-06-27T00:17:00.489Z', 'endDate': None, 'lastModified': '2021-05-31T18:44:35.555Z'}, 
        {'statName': 'TotalPlaytime', 'displayName': 'Total play time', 'value': total_playtime_sec, 'format': 'LongTimespan', 'unit': 'Seconds', 'startDate': '2020-06-27T00:13:00.766Z', 'endDate': None, 'lastModified': '2021-05-31T22:00:01.376Z'},
    ]
    assert [find_times(statscards=card) for card in cards][0] == total_playtime_min


def test_gametime_divition_2():
    total_playtime_min = 2
    game_time_in_game = 1111
    cards = [
        {'displayName': 'Daily Total Playtime', 'format': 'LongTimespan', 'statName': 'DailyPlaytimeAbsolute', 'unit': 'Seconds', 'value': game_time_in_game},
        {'displayName': 'Total Playtime', 'format': 'LongTimespan', 'statName': 'TotalAbsolutePlaytime', 'unit': 'Seconds', 'value': '128'},
        {'displayName': 'Dark Zone playtime', 'format': 'LongTimespan', 'statName': 'TotalPlaytimeDarkzone', 'unit': 'Seconds', 'value': '0'},
        {'displayName': 'Open-World Playtime', 'format': 'LongTimespan', 'statName': 'TotalPlaytimePve', 'unit': 'Seconds', 'value': '128'},
        {'displayName': 'Playtime against other players', 'format': 'LongTimespan', 'statName': 'TotalPlaytimePvp', 'unit': 'Seconds', 'value': '0'},
        {'displayName': 'Playtime as a Rogue', 'format': 'LongTimespan', 'statName': 'TotalPlaytimeRogue', 'unit': 'Seconds', 'value': '0'},
        {'displayName': 'Longest time spent as a Rogue', 'format': 'LongTimespan', 'statName': 'MaxRogueTime', 'unit': 'Seconds', 'value': ''}
    ]
    assert [find_times(statscards=card) for card in cards][0] == total_playtime_min
