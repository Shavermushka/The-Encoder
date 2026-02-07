import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import base64
import tempfile
from cryptography.fernet import Fernet
import hashlib

class SimpleEncryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифратор v2.3")
        self.root.geometry("850x750")
        
        # Переменные
        self.files = []
        
        self.create_widgets()
        
    def create_widgets(self):
        # Главный заголовок
        title = tk.Label(self.root, text="🔐 ШИФРАТОР 2.3", 
                        font=("Arial", 24, "bold"), fg="blue")
        title.pack(pady=15)
        
        # Фрейм для выбора файлов с кнопками
        file_buttons_frame = tk.Frame(self.root)
        file_buttons_frame.pack(pady=5)
        
        tk.Button(file_buttons_frame, text="📁 ВЫБРАТЬ ФАЙЛЫ", 
                 command=self.select_files,
                 bg="lightblue", font=("Arial", 10, "bold"),
                 padx=15, pady=8, width=15).pack(side=tk.LEFT, padx=5)
        
        tk.Button(file_buttons_frame, text="🗂️ ВЫБРАТЬ ПАПКУ", 
                 command=self.select_folder,
                 bg="lightgreen", font=("Arial", 10, "bold"),
                 padx=15, pady=8, width=15).pack(side=tk.LEFT, padx=5)
        
        tk.Button(file_buttons_frame, text="🗑️ ОЧИСТИТЬ СПИСОК", 
                 command=self.clear_files,
                 bg="#ff6b6b", fg="white", font=("Arial", 10, "bold"),
                 padx=15, pady=8, width=15).pack(side=tk.LEFT, padx=5)
        
        # Фрейм для информации о файлах
        file_info_frame = tk.Frame(self.root)
        file_info_frame.pack(pady=10, fill=tk.X, padx=20)
        
        self.file_count_label = tk.Label(file_info_frame, text="Файлов: 0", 
                                        font=("Arial", 10, "bold"), fg="blue")
        self.file_count_label.pack(side=tk.LEFT)
        
        self.total_size_label = tk.Label(file_info_frame, text="Общий размер: 0 Б", 
                                        font=("Arial", 10), fg="gray")
        self.total_size_label.pack(side=tk.LEFT, padx=20)
        
        # Список файлов
        list_frame = tk.LabelFrame(self.root, text="📄 Выбранные файлы", 
                                  font=("Arial", 10, "bold"), padx=10, pady=10)
        list_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        self.file_list = scrolledtext.ScrolledText(list_frame, height=8, 
                                                  font=("Consolas", 9), wrap=tk.WORD)
        self.file_list.pack(fill=tk.BOTH, expand=True)
        
        # Фрейм настроек
        settings_frame = tk.LabelFrame(self.root, text="⚙️ Настройки", 
                                      font=("Arial", 10, "bold"), padx=15, pady=15)
        settings_frame.pack(pady=15, padx=20, fill=tk.X)
        
        tk.Label(settings_frame, text="Метод:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.method_var = tk.StringVar(value="AES (рекомендуется)")
        methods = ["AES (рекомендуется)", "XOR", "Base64"]
        self.method_combo = ttk.Combobox(settings_frame, textvariable=self.method_var, 
                                        values=methods, state="readonly", width=25)
        self.method_combo.grid(row=0, column=1, padx=10, pady=5)
        
        tk.Label(settings_frame, text="Действие:").grid(row=0, column=2, sticky=tk.W, padx=10)
        self.action_var = tk.StringVar(value="encrypt")
        tk.Radiobutton(settings_frame, text="Зашифровать", 
                      variable=self.action_var, value="encrypt").grid(row=0, column=3, padx=5)
        tk.Radiobutton(settings_frame, text="Расшифровать", 
                      variable=self.action_var, value="decrypt").grid(row=0, column=4, padx=5)
        
        tk.Label(settings_frame, text="Пароль:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.password_entry = tk.Entry(settings_frame, show="•", width=25, font=("Arial", 10))
        self.password_entry.grid(row=1, column=1, pady=10, padx=10)
        
        tk.Button(settings_frame, text="🎲 Сгенерировать", 
                 command=self.generate_password,
                 bg="#ff9f43", fg="white", font=("Arial", 9)).grid(row=1, column=2, padx=10)
        
        options_frame = tk.Frame(settings_frame)
        options_frame.grid(row=2, column=0, columnspan=5, pady=10, sticky=tk.W)
        
        self.delete_var = tk.BooleanVar(value=False)
        tk.Checkbutton(options_frame, text="Удалить исходные файлы после обработки",
                      variable=self.delete_var).pack(side=tk.LEFT, padx=5)
        
        self.backup_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Создать резервные копии",
                      variable=self.backup_var).pack(side=tk.LEFT, padx=20)
        
        # Кнопки действий
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=15)
        
        tk.Button(button_frame, text="🚀 НАЧАТЬ ОБРАБОТКУ", 
                 command=self.process_files,
                 bg="#2ecc71", fg="white", font=("Arial", 12, "bold"),
                 padx=30, pady=12, width=20).pack(side=tk.LEFT, padx=10)
        
        tk.Button(button_frame, text="🧪 ПРОТЕСТИРОВАТЬ", 
                 command=self.run_test,
                 bg="#9b59b6", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=10, width=15).pack(side=tk.LEFT, padx=10)
        
        # Статус и прогресс
        status_frame = tk.Frame(self.root)
        status_frame.pack(pady=10, fill=tk.X, padx=20)
        
        self.status_label = tk.Label(status_frame, text="✅ Готов к работе", 
                                    font=("Arial", 10), fg="green")
        self.status_label.pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(self.root, length=800, mode='determinate')
        self.progress.pack(pady=5, padx=20)
        
        # Лог операций
        log_frame = tk.LabelFrame(self.root, text="📋 Лог операций", 
                                 font=("Arial", 10, "bold"), padx=10, pady=10)
        log_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, 
                                                 font=("Courier", 8))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log("Программа запущена. Выберите файлы для обработки.")
        
        tip_label = tk.Label(self.root, 
                            text="💡 Совет: Для удаления файлов из списка нажмите '🗑️ ОЧИСТИТЬ СПИСОК'",
                            font=("Arial", 9), fg="gray")
        tip_label.pack(pady=5)
    
    def log(self, message):
        """Добавление сообщения в лог"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def select_files(self):
        """Выбор файлов"""
        files = filedialog.askopenfilenames(title="Выберите файлы")
        if files:
            self.files.extend(files)
            self.update_file_list()
            self.log(f"Добавлено {len(files)} файлов")
    
    def select_folder(self):
        """Выбор папки"""
        folder = filedialog.askdirectory(title="Выберите папку")
        if folder:
            file_count = 0
            for root, dirs, files in os.walk(folder):
                for file in files:
                    self.files.append(os.path.join(root, file))
                    file_count += 1
            self.update_file_list()
            self.log(f"Добавлено {file_count} файлов из папки '{os.path.basename(folder)}'")
    
    def clear_files(self):
        """Очистка списка выбранных файлов"""
        if not self.files:
            self.log("⚠️ Список файлов уже пуст")
            return
        
        file_count = len(self.files)
        
        if messagebox.askyesno("Подтверждение", 
                              f"Вы уверены, что хотите очистить список?\n"
                              f"Будет удалено {file_count} файлов из списка."):
            self.files = []
            self.file_list.delete(1.0, tk.END)
            self.file_count_label.config(text="Файлов: 0")
            self.total_size_label.config(text="Общий размер: 0 Б")
            self.status_label.config(text="✅ Список очищен", fg="blue")
            self.log(f"🗑️ Список файлов очищен. Удалено {file_count} файлов")
            self.root.after(100, lambda: self.status_label.config(text="✅ Готов к работе", fg="green"))
    
    def update_file_list(self):
        """Обновление списка файлов"""
        self.file_list.delete(1.0, tk.END)
        
        total_size = 0
        
        for i, file in enumerate(self.files[-50:]):
            if os.path.exists(file):
                size = os.path.getsize(file)
                total_size += size
                filename = os.path.basename(file)
                
                if size < 1024:
                    size_str = f"{size} Б"
                elif size < 1024*1024:
                    size_str = f"{size/1024:.1f} КБ"
                elif size < 1024*1024*1024:
                    size_str = f"{size/(1024*1024):.1f} МБ"
                else:
                    size_str = f"{size/(1024*1024*1024):.1f} ГБ"
                
                self.file_list.insert(tk.END, f"{i+1:3d}. {filename} ({size_str})\n")
        
        file_count = len(self.files)
        self.file_count_label.config(text=f"Файлов: {file_count}")
        
        if total_size < 1024:
            total_size_str = f"{total_size} Б"
        elif total_size < 1024*1024:
            total_size_str = f"{total_size/1024:.1f} КБ"
        elif total_size < 1024*1024*1024:
            total_size_str = f"{total_size/(1024*1024):.1f} МБ"
        else:
            total_size_str = f"{total_size/(1024*1024*1024):.1f} ГБ"
        
        self.total_size_label.config(text=f"Общий размер: {total_size_str}")
        self.status_label.config(text=f"✅ Выбрано файлов: {file_count}", fg="green")
    
    def generate_password(self):
        """Генерация пароля"""
        import random
        import string
        
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(chars) for _ in range(16))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.log(f"🔑 Сгенерирован пароль: {password}")
    
    def get_fernet_key(self, password):
        """Получение ключа Fernet из пароля"""
        key = hashlib.sha256(password.encode()).digest()[:32]
        return base64.urlsafe_b64encode(key)
    
    def encrypt_aes(self, data, password):
        """Шифрование AES"""
        try:
            key = self.get_fernet_key(password)
            fernet = Fernet(key)
            return fernet.encrypt(data)
        except Exception as e:
            self.log(f"❌ Ошибка шифрования AES: {e}")
            return None
    
    def decrypt_aes(self, data, password):
        """Дешифрование AES"""
        try:
            key = self.get_fernet_key(password)
            fernet = Fernet(key)
            return fernet.decrypt(data)
        except Exception as e:
            self.log(f"❌ Ошибка дешифрования AES: {e}")
            return None
    
    def encrypt_xor(self, data, password):
        """Шифрование XOR"""
        if not password:
            password = "default_password"
        
        key = password.encode()
        key_len = len(key)
        result = bytearray()
        
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        return bytes(result)
    
    def encode_base64(self, data, password=None):
        """Кодирование Base64"""
        return base64.b64encode(data)
    
    def decode_base64(self, data, password=None):
        """Декодирование Base64"""
        return base64.b64decode(data)
    
    def get_file_extension(self, method):
        """Получение расширения файла для метода"""
        extensions = {
            "AES": ".enc",
            "XOR": ".xor",
            "Base64": ".b64"
        }
        return extensions.get(method, ".enc")
    
    def get_method_short_name(self, method_text):
        """Получение короткого имени метода из текста"""
        if "AES" in method_text:
            return "AES"
        elif "XOR" in method_text:
            return "XOR"
        elif "Base64" in method_text:
            return "Base64"
        else:
            return "AES"
    
    def process_files(self):
        """Обработка файлов"""
        if not self.files:
            messagebox.showwarning("⚠️ Внимание", "Сначала выберите файлы!")
            return
        
        method = self.get_method_short_name(self.method_var.get())
        action = self.action_var.get()
        password = self.password_entry.get()
        delete_original = self.delete_var.get()
        create_backup = self.backup_var.get()
        
        if method == "AES" and not password:
            messagebox.showerror("❌ Ошибка", "Для метода AES требуется пароль!")
            return
        
        self.progress['maximum'] = len(self.files)
        self.progress['value'] = 0
        
        success_count = 0
        error_count = 0
        
        extension = self.get_file_extension(method)
        
        for i, file_path in enumerate(self.files):
            try:
                if not os.path.exists(file_path):
                    self.log(f"❌ Файл не найден: {file_path}")
                    continue
                
                if create_backup and action == "encrypt":
                    backup_path = file_path + ".backup"
                    import shutil
                    shutil.copy2(file_path, backup_path)
                    self.log(f"📋 Создана резервная копия: {os.path.basename(backup_path)}")
                
                if action == "encrypt":
                    output_path = file_path + extension
                else:
                    if file_path.endswith(extension):
                        output_path = file_path[:-len(extension)]
                    else:
                        base_name, ext = os.path.splitext(file_path)
                        output_path = base_name + "_decrypted" + ext
                
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                self.log(f"🔄 Обработка: {os.path.basename(file_path)} -> {os.path.basename(output_path)}")
                
                if action == "encrypt":
                    if method == "AES":
                        processed_data = self.encrypt_aes(data, password)
                    elif method == "XOR":
                        processed_data = self.encrypt_xor(data, password)
                    elif method == "Base64":
                        processed_data = self.encode_base64(data)
                else:
                    if method == "AES":
                        processed_data = self.decrypt_aes(data, password)
                    elif method == "XOR":
                        processed_data = self.encrypt_xor(data, password)
                    elif method == "Base64":
                        processed_data = self.decode_base64(data)
                
                if processed_data is None:
                    raise Exception("Ошибка обработки данных")
                
                with open(output_path, 'wb') as f:
                    f.write(processed_data)
                
                if delete_original:
                    os.remove(file_path)
                    self.log(f"🗑️ Удален исходный файл: {os.path.basename(file_path)}")
                
                success_count += 1
                self.log(f"✅ Успешно обработан: {os.path.basename(output_path)}")
                
            except Exception as e:
                error_count += 1
                self.log(f"❌ Ошибка при обработке {os.path.basename(file_path)}: {str(e)}")
            
            self.progress['value'] = i + 1
            self.status_label.config(text=f"Обработано: {i+1}/{len(self.files)}")
            self.root.update()
        
        result_text = f"""
✅ ОБРАБОТКА ЗАВЕРШЕНА!

Успешно: {success_count} файлов
Ошибок: {error_count} файлов

📂 Файлы сохранены в ту же папку
🔑 Для расшифровки используйте тот же метод и пароль
"""
        
        messagebox.showinfo("🎉 Готово", result_text)
        
        self.progress['value'] = 0
        self.status_label.config(text="✅ Готов к работе", fg="green")
        self.log("="*50)
        self.log(f"Обработка завершена. Успешно: {success_count}, Ошибок: {error_count}")
    
    def run_test(self):
        """ИСПРАВЛЕННЫЙ ТЕСТ с правильным созданием тестового файла"""
        self.log("\n" + "="*60)
        self.log("🧪 ЗАПУСК ПОЛНОГО ТЕСТА ШИФРОВАНИЯ ФАЙЛОВ")
        self.log("="*60)
        
        test_password = "TestPassword123!"
        
        try:
            # Создаем временный тестовый файл
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as tmp:
                # ИСПРАВЛЕНО: используем байтовые строки без кириллицы
                test_content = b"Test file content for encryption!\n" + \
                               b"Second line of test content.\n" + \
                               b"Third line with symbols: !@#$%^&*()\n"
                tmp.write(test_content)
                temp_file_path = tmp.name
            
            self.log(f"\n📄 Создан тестовый файл: {os.path.basename(temp_file_path)}")
            self.log(f"📏 Размер файла: {len(test_content)} байт")
            
            # Тестируем все методы
            methods_to_test = ["AES", "XOR", "Base64"]
            
            for method in methods_to_test:
                self.log(f"\n{'='*40}")
                self.log(f"🔍 ТЕСТИРУЕМ МЕТОД: {method}")
                self.log(f"{'='*40}")
                
                try:
                    extension = self.get_file_extension(method)
                    
                    # 1. Шифруем файл
                    self.log(f"1. Шифрование файла методом {method}...")
                    
                    with open(temp_file_path, 'rb') as f:
                        original_data = f.read()
                    
                    if method == "AES":
                        encrypted_data = self.encrypt_aes(original_data, test_password)
                    elif method == "XOR":
                        encrypted_data = self.encrypt_xor(original_data, test_password)
                    elif method == "Base64":
                        encrypted_data = self.encode_base64(original_data)
                    
                    if encrypted_data is None:
                        self.log(f"❌ Ошибка при шифровании методом {method}")
                        continue
                    
                    # Сохраняем зашифрованный файл
                    encrypted_file = temp_file_path + extension
                    with open(encrypted_file, 'wb') as f:
                        f.write(encrypted_data)
                    
                    self.log(f"✅ Файл зашифрован: {os.path.basename(encrypted_file)}")
                    self.log(f"📏 Размер зашифрованного файла: {len(encrypted_data)} байт")
                    
                    # 2. Дешифруем файл
                    self.log(f"2. Дешифрование файла методом {method}...")
                    
                    with open(encrypted_file, 'rb') as f:
                        encrypted_data_read = f.read()
                    
                    if method == "AES":
                        decrypted_data = self.decrypt_aes(encrypted_data_read, test_password)
                    elif method == "XOR":
                        decrypted_data = self.encrypt_xor(encrypted_data_read, test_password)
                    elif method == "Base64":
                        decrypted_data = self.decode_base64(encrypted_data_read)
                    
                    if decrypted_data is None:
                        self.log(f"❌ Ошибка при дешифровании методом {method}")
                        continue
                    
                    # Сохраняем дешифрованный файл
                    decrypted_file = temp_file_path + "_decrypted" + ".txt"
                    with open(decrypted_file, 'wb') as f:
                        f.write(decrypted_data)
                    
                    self.log(f"✅ Файл дешифрован: {os.path.basename(decrypted_file)}")
                    
                    # 3. Проверяем совпадение
                    self.log(f"3. Проверка совпадения исходного и дешифрованного файлов...")
                    
                    if original_data == decrypted_data:
                        self.log(f"🎉 ТЕСТ ПРОЙДЕН! Метод {method} работает корректно!")
                        
                        # Показываем небольшой пример содержимого
                        if len(decrypted_data) < 200:
                            try:
                                content_preview = decrypted_data[:50].decode('utf-8', errors='ignore')
                                self.log(f"📝 Пример содержимого: {content_preview}...")
                            except:
                                pass
                    else:
                        self.log(f"❌ ТЕСТ НЕ ПРОЙДЕН! Метод {method} работает некорректно!")
                        self.log(f"   Исходный размер: {len(original_data)} байт")
                        self.log(f"   Дешифрованный размер: {len(decrypted_data)} байт")
                    
                    # 4. Очищаем временные файлы
                    if os.path.exists(encrypted_file):
                        os.remove(encrypted_file)
                        self.log(f"🗑️ Удален временный файл: {os.path.basename(encrypted_file)}")
                    
                    if os.path.exists(decrypted_file):
                        os.remove(decrypted_file)
                        self.log(f"🗑️ Удален временный файл: {os.path.basename(decrypted_file)}")
                    
                except Exception as e:
                    self.log(f"❌ Ошибка при тестировании метода {method}: {str(e)}")
                    import traceback
                    self.log(f"   Детали: {traceback.format_exc()}")
            
            # Удаляем исходный временный файл
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
                self.log(f"\n🗑️ Удален исходный тестовый файл")
            
            self.log("\n" + "="*60)
            self.log("🎉 ПОЛНЫЙ ТЕСТ ЗАВЕРШЕН!")
            self.log("="*60)
            
            # Показываем результат в отдельном окне
            test_window = tk.Toplevel(self.root)
            test_window.title("Результаты тестирования")
            test_window.geometry("600x400")
            
            test_text = scrolledtext.ScrolledText(test_window, font=("Courier", 9))
            test_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Читаем последние 50 строк из лога
            log_content = self.log_text.get("1.0", tk.END)
            lines = log_content.split('\n')
            test_lines = [line for line in lines if "ТЕСТ" in line or "метод" in line or "Ошибка" in line or "✅" in line or "❌" in line]
            last_test = '\n'.join(test_lines[-50:])
            
            test_text.insert(1.0, last_test)
            test_text.config(state='disabled')
            
            tk.Button(test_window, text="Закрыть", 
                     command=test_window.destroy,
                     bg="#3498db", fg="white",
                     font=("Arial", 10, "bold"),
                     padx=20, pady=10).pack(pady=10)
            
        except Exception as e:
            self.log(f"❌ КРИТИЧЕСКАЯ ОШИБКА ПРИ ТЕСТИРОВАНИИ: {str(e)}")
            import traceback
            self.log(f"Детали: {traceback.format_exc()}")

def main():
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("Установка библиотеки cryptography...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
        print("Перезапустите программу!")
        return
    
    root = tk.Tk()
    app = SimpleEncryptor(root)
    
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()