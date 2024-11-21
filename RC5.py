class RC5:

    def __init__(self, W: int = 32, R: int = 12, key: str ='keyWord'):
        self.W = self.__checkW(W)
        self.R = self.__checkR(R)
        self.b = len(key)
        self.T = 2 * (self.R + 1)
        self.key = bytes(key, 'utf-8')
        self.mod = 2 ** self.W
        self.mask = self.mod - 1
        self.W8 = self.W // 8
        self.W4 = self.W // 4
        self.P, self.Q = self.__generateConstants()
        self.c = 0
        self.L = []
        self.S = []

        self.__generateConstants()
        self.__keyAlign()
        self.extendedKeyTable()
        self.__mixing()
        # self.eStr = self.encryptString("Это зашифрованное сообщение");
        # print(eStr)
        # print(self.decryptStringData(eStr))
        # self.extendedKeyTable()

        # res = self.encryptString("Привет, это зашифрованный текст")
        # print(res)
        # print(self.decryptStringData(res))
    # Проверка введенного W
    def __checkW(self, W):
        match W:
            case 16:
                return 16
            case 32:
                return 32
            case 64:
                return 64
            case _:
                raise ValueError(f"Недопустимое значение W: {W}. Ожидалось 16, 32 или 64.")

    # Проверка введенного R
    def __checkR(self, R):
        if (R < 0 | R > 255):
            raise ValueError(f"Недопустимое значение R: {R}. Ожидалось целочисленное значение от 0 до 255")
        else:
            return R

    # Создаем псевдо-случйные константы
    def __generateConstants(self):
        match self.W:
            case 16:
                return (0xB7E1, 0x9E37)
            case 32:
                return (0xB7E15163, 0x9E3779B9)
            case 64:
                return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

    # Создаем массив слов L с длиной c = b/W8
    def __keyAlign(self):
        if self.b == 0: # пустой ключ
            self.c = 1
        elif self.b % self.W8: # ключ не кратен w / 8
            self.key += b'\x00' * (self.W8 - self.b % self.W8) # дополняем ключ байтами \x00
            self.b = len(self.key)
            self.c = self.b // self.W8
        else:
            self.c = self.b // self.W8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1): # Заполняем массив L
            L[i // self.W8] = (L[i // self.W8] << 8) + self.key[i]
        self.L = L


    # Заполняем таблицу расширенных ключей
    # def extendedKeyTable(self):
        # self.S = [0] * self.T # Задаем размерность таблицы S
        # self.S[0] = self.P
        # for i in range(1, self.T, 1):
        #     self.S[i] = self.S[i-1] + self.Q

    # Заполняем таблицу расширенных ключей
    def extendedKeyTable(self):
        self.S = [(self.P + i * self.Q) % self.mod for i in range(self.T)]

    # Перемешивание
    def __mixing(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

    def __lshift(self, val, n):
        n %= self.W
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.W - n))

    def __rshift(self, val, n):
        n %= self.W
        return ((val & self.mask) >> n) | (val << (self.W - n) & self.mask)

    def encryptBlock(self, data):
        A = int.from_bytes(data[:self.W8], byteorder='little')
        B = int.from_bytes(data[self.W8:], byteorder='little')
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.R + 1):
            A = (self.__lshift((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.__lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod
        return (A.to_bytes(self.W8, byteorder='little')
                + B.to_bytes(self.W8, byteorder='little'))

    def encryptString(self, text):
        run = True
        encrypted_data = b''  # Для хранения зашифрованных байт

        # Преобразуем строку в байты для обработки
        text_bytes = text.encode('utf-8')

        # Разбиваем строку на блоки длиной self.w4 (байты)
        for i in range(0, len(text_bytes), self.W4):
            block = text_bytes[i:i + self.W4]

            # Проверяем, нужно ли дополнить блок
            if len(block) < self.W4:
                block = block.ljust(self.W4, b'\x00')  # Дополняем нулевыми байтами
                run = False


            encrypted_block = self.encryptBlock(block)
            encrypted_data += encrypted_block

            if not run:
                break
        self.eStr = encrypted_data
        return encrypted_data

    def decryptBlock(self, data):
        data = self.eStr
        A = int.from_bytes(data[:self.W8], byteorder='little')
        B = int.from_bytes(data[self.W8:], byteorder='little')
        for i in range(self.R, 0, -1):
            B = self.__rshift(B - self.S[2 * i + 1], A) ^ A
            A = self.__rshift(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return (A.to_bytes(self.W8, byteorder='little')
                + B.to_bytes(self.W8, byteorder='little'))


    def decryptStringData(self, encrypted_data: bytes):
        decrypted_data = b''


        for i in range(0, len(encrypted_data), self.W4):
            block = encrypted_data[i:i + self.W4]

            decrypted_block = self.decryptBlock(block)
            decrypted_data += decrypted_block

        decrypted_data = decrypted_data.rstrip(b'\x00')


        try:

            return decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            print("Ошибка декодирования. Возможно, исходные данные не являются строкой UTF-8.")
            return "Ошибка декодирования. Возможно, исходные данные не являются строкой UTF-8."


if (__name__ == "__main__"):

    RC5(W=32, R=12, key="keyWord")
