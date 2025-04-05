        self.__password = None
        self.__key = key
        self.__aes = acrypt(KEY_EXTRA + self.__key)
        self._instances.append(self)

    def __encode_message(self, message) -> bytes:
        """Превращает объекты, преобразоваемые в JSON в байты."""
        return self.__aes.encrypt(dumps(
            message,
            separators=(",", ":"),
            ensure_ascii=False
        ))

    def __decode_message(self, message: bytes):
        """Превращает байты в объекты, преобразоваемые в JSON."""
        return loads(self.__aes.decrypt(message))

    def send(self, message: list) -> None:
        """Отправляет сообщение клиенту.

        Аргументы:
            message:    Сообщение.
        """
        print("Отправлено клиенту:", message)
        encoded = self.__encode_message(message)
        self.sock.sendto(encoded, self.addr)

    def send_account_data(self) -> None:
        """Отправляет данные об аккаунте."""
        if self.login is None:
            return

        adata = dtb.get_account_data(self.login)

        self.send(["account_data", adata[0]])
