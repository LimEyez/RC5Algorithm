from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from RC5 import RC5

rc5_instance = None  # Глобальная переменная для хранения экземпляра RC5
params_saved = False  # Флаг для проверки, что параметры были сохранены

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


def validate_inputs(w, r, key):
    if w not in [16, 32, 64]:
        return False, "Значение W должно быть 16, 32 или 64."
    if not (0 <= r <= 255):
        return False, "Значение R должно быть числом от 0 до 255."
    if len(key) > 255:
        return False, "Длина ключа не может превышать 255 символов."
    return True, ""


def createWindow():
    global rc5_instance, params_saved
    root = Tk()
    root.title("RC5 Алгоритм")
    root.geometry("800x800")

    scroll_frame = ScrollableFrame(root)
    scroll_frame.pack(fill="both", expand=True)
    frame = scroll_frame.scrollable_frame

    message_w = StringVar()
    message_r = StringVar()

    label_w = ttk.Label(frame, text="Введите значение W (16,32,64)", font=("Arial", 14))
    label_w.pack(pady=10)

    input_w = ttk.Entry(frame, textvariable=message_w, width=10, font=("Arial", 14), justify="center")
    input_w.pack(pady=10, ipady=10)

    label_r = ttk.Label(frame, text="Введите значение R (0, ..., 255):", font=("Arial", 14))
    label_r.pack(pady=10)

    input_r = ttk.Entry(frame, textvariable=message_r, width=10, font=("Arial", 14), justify="center")
    input_r.pack(pady=10, ipady=10)

    label_key = ttk.Label(frame, text="Введите ключ-слово с максимальной длиной 255 символов:", font=("Arial", 14))
    label_key.pack(pady=10)

    input_key = Text(frame, height=5, font=("Arial", 14), width=50)
    input_key.pack(pady=10, ipady=10)

    def on_save_params():
        global rc5_instance, params_saved
        try:
            w = int(message_w.get())
            r = int(message_r.get())
            key = input_key.get("1.0", "end-1c")

            valid, error_message = validate_inputs(w, r, key)

            if not valid:
                messagebox.showerror("Ошибка", error_message)
                params_saved = False
            else:
                rc5_instance = RC5(w, r, key)
                params_saved = True
                messagebox.showinfo("Успех", "Данные успешно сохранены!")
        except ValueError:
            messagebox.showerror("Ошибка", "W и R должны быть целыми числами.")
            params_saved = False

    btn_saveParams = ttk.Button(frame, text="Сохранить данные шифрования", command=on_save_params)
    btn_saveParams.pack(pady=10, ipady=10)

    label_message = ttk.Label(frame, text="Сообщение для шифрования:", font=("Arial", 14))
    label_message.pack(pady=10)

    input_message = Text(frame, height=5, font=("Arial", 14), width=50)
    input_message.pack(pady=10, ipady=10)

    def on_encrypt_message():
        if not params_saved or not rc5_instance:
            messagebox.showerror("Ошибка", "Сначала сохраните параметры.")
            return

        message = input_message.get("1.0", "end-1c").strip()
        if not message:
            messagebox.showerror("Ошибка", "Сообщение для шифрования не может быть пустым.")
            return

        encrypted_message = rc5_instance.encryptFile(message)
        input_encryptMessage.delete("1.0", "end")
        input_encryptMessage.insert("1.0", encrypted_message)
        messagebox.showinfo("Успех", "Сообщение успешно зашифровано!")

    btn_encryptMessage = ttk.Button(frame, text="Зашифровать сообщение", command=on_encrypt_message)
    btn_encryptMessage.pack(pady=10, ipady=10)

    label_message = ttk.Label(frame, text="Зашифрованное сообщение:", font=("Arial", 14))
    label_message.pack(pady=10)

    input_encryptMessage = Text(frame, height=5, font=("Arial", 14), width=50)
    input_encryptMessage.pack(pady=10, ipady=10)

    def on_decrypt_message():
        if not params_saved or not rc5_instance:
            messagebox.showerror("Ошибка", "Сначала сохраните параметры.")
            return

        encrypted_message = input_encryptMessage.get("1.0", "end-1c").strip()
        if not encrypted_message:
            messagebox.showerror("Ошибка", "Не удается расшифровать сообщение. На этапе шифрования произошла ошибка")
            return

        decrypted_message = rc5_instance.decryptFile(encrypted_message)
        input_decryptMessage.delete("1.0", "end")
        input_decryptMessage.insert("1.0", decrypted_message.decode("utf-8"))
        messagebox.showinfo("Успех", "Сообщение успешно расшифровано!")

    btn_decryptMessage = ttk.Button(frame, text="Расшифровать сообщение", command=on_decrypt_message)
    btn_decryptMessage.pack(pady=10, ipady=10)

    label_message = ttk.Label(frame, text="Расшифрованное сообщение:", font=("Arial", 14))
    label_message.pack(pady=10)

    input_decryptMessage = Text(frame, height=5, font=("Arial", 14), width=50)
    input_decryptMessage.pack(pady=10, ipady=10)

    root.mainloop()

if __name__ == "__main__":
    createWindow()
