        self._is_on_main_tab: bool = False
        self.__temp_messages: list = []
        self.__key = None
        self.__aes = None
        self.destroyed = False
        self.__queued_requests = []
        self.__last_login = None
        self.__last_password = None

        Thread(target=self.receive, daemon=True).start()
        Thread(target=self.send_idle, daemon=True).start()

        self.main()

        if not self.destroyed:
            self._sock.send(b"\x05\x03\xff\x01")

    @staticmethod
    def show_error(title: str, message: str) -> None:
        """Показывает ошибку.

        Аргументы:
            title:      Заголовок ошибки.
            message:    Описание ошибки.
        """
        title = f"ОШИБКА: {title}"
        ltitle = len(title)
        lmessage = len(message)
        mlen = max(ltitle, lmessage)
        dtitle = (mlen - ltitle) / 2
        dmessage = (mlen - lmessage) / 2
        print("-" * (mlen + 4))
        print(f"|{' ' * (floor(dtitle) + 1)}{title}\
{' ' * (ceil(dtitle) + 1)}|")
        print("-" * (mlen + 4))
        print(f"|{' ' * (floor(dmessage) + 1)}{message}\
{' ' * (ceil(dmessage) + 1)}|")
        print("-" * (mlen + 4))

    def __encode_message(self, message) -> bytes:
        """Превращает объекты, преобразоваемые в JSON в байты."""
        if self.__key is None and not self.destroyed:
            self._sock.send(b"\x05\x03\xff\x01")
            self.__queued_requests.append(message)
            return None

        return self.__aes.encrypt(dumps(
            message,
            separators=(",", ":"),
            ensure_ascii=False
        ))

    def __decode_message(self, message: bytes):
        """Превращает байты в объекты, преобразоваемые в JSON."""
        if self.__key is None:
            self.__key = message.decode("ascii")
            self.__aes = acrypt(KEY_EXTRA + self.__key)

            for req in self.__queued_requests:
                self.send(req)

            return False

        return loads(self.__aes.decrypt(message))

    def send(self, message) -> None:
        """Отправляет сообщение message на сервер.

        Аргументы:
            message:    Сообщение.
        """
        msg = self.__encode_message(message)

        if msg is not None:
            self._sock.send(msg)

    def send_register(self, login, password):
        """Присылает сообщение регистрации на сервер."""
        self.__last_login = login
        self.__last_password = password
        self.send(["register", login, password])

    def send_login(self, login, password):
        """Присылает сообщение входа в аккаунт на сервер."""
        self.__last_login = login
        self.__last_password = password
        self.send(["login", login, password])

    def remember_login(self):
        """Записывает логин и пароль для дальнейшего автоматического входа."""
        if self.__last_login is None or self.__last_password is None:
            return False

        login = str(self.__last_login)
        password = str(self.__last_password)

        with open(absolute(".logindata"), "wb") as lfile:
            lfile.write(
                acrypt(KEY_LOGIN_FILE).encrypt("\n".join([login, password]))
            )
