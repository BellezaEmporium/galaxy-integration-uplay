import logging as log
from definitions import GameStatus, UbisoftGame


class GamesCollection(list):

    def get_local_games(self):
        return [game for game in self if game.status in {GameStatus.Installed, GameStatus.Running}]

    def append(self, _):
        raise AssertionError("Method not available. Use extend")

    def _extend_existing_game_entry(self, game: UbisoftGame) -> None:
        for existing in self:
            if not (
                (game.space_id   and game.space_id   == existing.space_id)   or
                (game.install_id and game.install_id == existing.install_id) or
                (game.launch_id  and game.launch_id  == existing.launch_id)  or
                (game.launch_id  and game.launch_id  == existing.install_id)
            ):
                continue

            if (game.install_id and game.launch_id
                    and game.install_id != game.launch_id
                    and existing.install_id == existing.launch_id):
                log.debug(f"Updating ids for {existing.name}: launch={game.launch_id} install={game.install_id}")
                existing.install_id = game.install_id
                existing.launch_id  = game.launch_id

            if game.install_id and not existing.install_id:
                log.debug(f"Filling install/launch id for {existing.name}")
                existing.install_id = game.install_id
                existing.launch_id  = game.launch_id

            if game.space_id and not existing.space_id:
                log.debug(f"Filling space_id for {existing.name}: {game.space_id}")
                existing.space_id = game.space_id

            if game.status is not GameStatus.Unknown and existing.status is GameStatus.Unknown:
                log.debug(f"Filling status for {existing.name}: {game.status}")
                existing.status = game.status

            if game.owned is True and not existing.owned:
                log.debug(f"Marking {existing.name} as owned")
                existing.owned = True

            if game.activation_id and not existing.activation_id:
                log.debug(f"Filling activation_id for {existing.name}: {game.activation_id}")
                existing.activation_id = game.activation_id

            return

    def extend(self, games) -> None:
        spaces   = {g.space_id   for g in self if g.space_id}
        installs = {g.install_id for g in self if g.install_id}
        launches = {g.launch_id  for g in self if g.launch_id}

        for game in games:
            already_known = (
                (game.space_id   and game.space_id   in spaces)   or
                (game.install_id and game.install_id in installs)  or
                (game.launch_id  and game.launch_id  in launches)  or
                (game.launch_id  and game.launch_id  in installs)
            )

            if not already_known:
                if game.name == "Unknown":
                    log.debug(f"Skipping unnamed game {game.space_id}/{game.launch_id}")
                    continue
                if game.space_id:   spaces.add(game.space_id)
                if game.install_id: installs.add(game.install_id)
                if game.launch_id:  launches.add(game.launch_id)
                log.info(f"Adding {game.name} [{game.space_id} / {game.launch_id}/{game.install_id}]")
                super().append(game)
            else:
                self._extend_existing_game_entry(game)

    def __getitem__(self, key: int | str) -> UbisoftGame:
        if isinstance(key, int):
            return super().__getitem__(key)
        if isinstance(key, str):
            for game in self:
                if key in (game.launch_id, game.space_id, game.install_id):
                    return game
            raise KeyError(f"No game with id: {key}")
        raise TypeError(f"Expected str or int, got {type(key).__name__}")

    def get(self, key: int | str) -> UbisoftGame | None:
        try:
            return self.__getitem__(key)
        except (KeyError, TypeError):
            return None