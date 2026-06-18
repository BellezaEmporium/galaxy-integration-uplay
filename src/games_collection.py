import logging as log
from definitions import GameStatus, UbisoftGame


class GamesCollection(list):

    def get_local_games(self):
        return [game for game in self if game.status in {GameStatus.Installed, GameStatus.Running}]

    def append(self, _):
        AssertionError('Method not available. Use extend')

    def _extend_existing_game_entry(self, game):
        for game_in_list in self:
            if (game.space_id and game.space_id == game_in_list.space_id) or (game.install_id and game.install_id == game_in_list.install_id) or \
                    (game.launch_id and game.launch_id == game_in_list.launch_id):
                if game.install_id and game.launch_id and game.install_id != game.launch_id and (game_in_list.install_id == game_in_list.launch_id):
                    log.debug(f"Extending existing game entry {game_in_list} with more specific install/launch id launch id: {game.launch_id} and install id: {game.install_id}")
                    game_in_list.install_id = game.install_id
                    game_in_list.launch_id = game.launch_id
                if game.install_id and not game_in_list.install_id:
                    log.debug(f"Extending existing game entry {game_in_list} with launch id: {game.launch_id} and install id: {game.install_id}")
                    game_in_list.install_id = game.install_id
                    game_in_list.launch_id = game.launch_id
                if game.space_id and not game_in_list.space_id:
                    log.debug(f"Extending existing game entry {game_in_list} with space id: {game.space_id}")
                    game_in_list.space_id = game.space_id
                if game.status is not GameStatus.Unknown and game_in_list.status is GameStatus.Unknown:
                    log.debug(f"Extending existing game entry {game_in_list} with installation status: {game.status}")
                    game_in_list.status = game.status
                if game.owned is not None:
                    log.debug(f"Extending existing game entry {game_in_list} with owned status: {game.owned}")
                    game_in_list.owned = game.owned
                if game.activation_id:
                    log.debug(f"Extending existing game entry {game_in_list} with activation_id: {game.activation_id}")
                    game_in_list.activation_id = game.activation_id

    def extend(self, games):
        spaces = {game.space_id for game in self if game.space_id}
        installs = {game.install_id for game in self if game.install_id}
        launches = {game.launch_id for game in self if game.launch_id}

        for game in games:
            is_new = (
                game.space_id not in spaces
                and game.install_id not in installs
                and game.launch_id not in launches
                and game.launch_id not in installs
                and game.name != "Unknown"
            )
            if is_new:
                if game.space_id:
                    spaces.add(game.space_id)
                if game.install_id:
                    installs.add(game.install_id)
                if game.launch_id:
                    launches.add(game.launch_id)
                log.info(f"Adding new game to collection {game.name} {game.space_id} {game.launch_id}/{game.install_id}")
                super().append(game)
            else:
                self._extend_existing_game_entry(game)

    def __getitem__(self, key: int | str) -> UbisoftGame:
        if isinstance(key, int):
            return super().__getitem__(key)
        if isinstance(key, str):
            for game in self:
                if key in (game.launch_id, game.space_id):
                    return game
            raise KeyError(f"No game with id: {key}")
        raise TypeError(f"Expected str or int, got {type(key).__name__}")

    def get(self, key: int | str) -> UbisoftGame | None:
        try:
            return self.__getitem__(key)
        except (KeyError, TypeError):
            return None
