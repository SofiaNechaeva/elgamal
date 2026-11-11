import tkinter as tk
from tkinter import ttk, messagebox
from crypto.elgamal import make_keys, verify, hash_bytes, Signature
from crypto.key_store import save_keys, load_keys
from communication.transport import LocalTransport
from application.services import Sender, Receiver


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Эль-Гамаль: отправитель А')
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = min(760, max(1, (screen_width - 40) // 2))
        window_height = min(840, max(1, screen_height - 80))
        self.geometry(f'{window_width}x{window_height}+0+0')
        self.receiver_window = tk.Toplevel(self)
        self.receiver_window.title('Эль-Гамаль: получатель Б')
        self.receiver_window.geometry(
            f'{window_width}x{window_height}+{window_width + 20}+0'
        )
        self.receiver_window.protocol('WM_DELETE_WINDOW', self.destroy)
        self.transport = LocalTransport()
        self.sender, self.receiver = Sender(self.transport), Receiver(self.transport)
        self.public = self.private = None
        self._build()
        try:
            self.public, self.private = load_keys()
            self.key_info.set(self._key_description())
            self._log(self.key_log, 'Загружены ранее сохранённые ключи.\n')
        except (OSError, ValueError, KeyError):
            pass

    def _build(self):
        style = ttk.Style(self)
        style.configure('Title.TLabel', font=('Arial', 12, 'bold'))
        outer = ttk.Frame(self, padding=10)
        outer.pack(fill='both', expand=True)
        keys = ttk.LabelFrame(outer, text='1. Одноразовая генерация ключей (можно перезапустить)', padding=8)
        keys.pack(fill='x')
        ttk.Label(keys, text='p (необязательно):').pack(side='left')
        self.p_entry = ttk.Entry(keys, width=18)
        self.p_entry.pack(side='left', padx=5)
        self.p_entry.insert(0, '23')
        ttk.Label(keys, text='бит (если p пусто):').pack(side='left', padx=(12,2))
        self.bits = ttk.Combobox(keys, values=['16','32','64','128','256'], width=6, state='readonly')
        self.bits.set('32'); self.bits.pack(side='left')
        ttk.Button(keys, text='Сгенерировать заново', command=self.generate).pack(side='left', padx=10)
        ttk.Button(keys, text='Загрузить сохранённые', command=self.load).pack(side='left')
        ttk.Button(keys, text='Заново', command=self.reset_workflow).pack(side='right')
        self.key_info = tk.StringVar(value='Ключи ещё не созданы')
        ttk.Label(outer, textvariable=self.key_info, wraplength=700).pack(fill='x', pady=5)
        self.key_log = self._text(outer, height=7)
        left = ttk.LabelFrame(outer, text='2. ОТПРАВИТЕЛЬ А', padding=8)
        left.pack(fill='both', expand=True, pady=8)
        right = ttk.LabelFrame(self.receiver_window, text='3. ПОЛУЧАТЕЛЬ Б', padding=8)
        right.pack(fill='both', expand=True, padx=10, pady=10)
        ttk.Label(left, text='Сообщение для подписи:').pack(anchor='w')
        self.message = self._text(left, height=5)
        self.message.insert('1.0', 'Привет, Б! Это сообщение подписано Эль-Гамалем.')
        bar = ttk.Frame(left); bar.pack(fill='x', pady=5)
        ttk.Button(bar, text='1. Подписать', command=self.sign_message).pack(side='left')
        ttk.Button(bar, text='2. Отправить →', command=self.send_signed).pack(side='left', padx=5)
        self.sender_status = tk.StringVar(value='Ожидание подписи')
        ttk.Label(left, textvariable=self.sender_status, style='Title.TLabel').pack(anchor='w', pady=3)
        ttk.Label(left, text='Формулы и подстановки отправителя:').pack(anchor='w')
        self.sender_log = self._text(left, height=20)
        self.sender_log.tag_configure('sent', foreground='#087830', font=('DejaVu Sans Mono', 10, 'bold'))
        ttk.Label(right, text='Принятое сообщение (можно изменить для проверки подмены):').pack(anchor='w')
        self.received = self._text(right, height=3)
        bar2 = ttk.Frame(right); bar2.pack(fill='x', pady=5)
        ttk.Button(bar2, text='1. Получить ←', command=self.receive_packet).pack(side='left')
        ttk.Button(bar2, text='2. Проверить', command=self.verify_edited).pack(side='left', padx=5)
        ttk.Label(right, text='Подпись для проверки (её можно изменить):').pack(anchor='w')
        signature_frame = ttk.Frame(right)
        signature_frame.pack(fill='x', pady=(2, 5))
        ttk.Label(signature_frame, text='a =').pack(side='left')
        self.a_entry = ttk.Entry(signature_frame, width=18)
        self.a_entry.pack(side='left', padx=(4, 14))
        ttk.Label(signature_frame, text='b =').pack(side='left')
        self.b_entry = ttk.Entry(signature_frame, width=18)
        self.b_entry.pack(side='left', padx=4)
        ttk.Label(right, text='Полученный h(M):').pack(anchor='w')
        self.received_hash = tk.StringVar(value='')
        ttk.Entry(right, textvariable=self.received_hash, width=72, state='readonly').pack(fill='x', pady=(2, 5))
        self.status = tk.StringVar(value='Ожидание сообщения')
        ttk.Label(right, textvariable=self.status, style='Title.TLabel').pack(anchor='w', pady=3)
        ttk.Label(right, text='Формулы и подстановки получателя:').pack(anchor='w')
        self.receiver_log = self._text(right, height=20)
        self.last_signature = None
        self.last_message = None
        self.last_hash = None
        self.pending_message = self.pending_signature = None

    def _text(self, parent, height):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=(height >= 20), pady=2)
        widget = tk.Text(frame, height=height, wrap='word', font=('DejaVu Sans Mono', 10), undo=True)
        scroll = ttk.Scrollbar(frame, orient='vertical', command=widget.yview)
        widget.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        widget.pack(side='left', fill='both', expand=True)
        return widget

    def _log(self, widget, content):
        widget.delete('1.0','end')
        widget.insert('1.0', content)

    def _key_description(self):
        return f'Открытый: p={self.public.p}; A={self.public.A}; y={self.public.y}  |  Закрытый xᵢ хранится только у А в keys/private.json'

    def generate(self):
        try:
            raw = self.p_entry.get().strip()
            p = int(raw) if raw else None
            pub, priv, log = make_keys(int(self.bits.get()), p)
            self.public, self.private = pub, priv
            save_keys(pub, priv)
            self.key_info.set(self._key_description())
            self._log(self.key_log, log)
            self._log(self.sender_log, '')
            self._log(self.receiver_log, '')
            self.status.set('Ключи обновлены. Ожидание сообщения')
            self.sender_status.set('Ключи обновлены. Ожидание подписи')
            self.last_signature = self.last_message = None
            self.last_hash = None
            self.pending_message = self.pending_signature = None
            # Старые пакеты удаляем, чтобы не проверять их новым ключом.
            self.transport = LocalTransport()
            self.sender, self.receiver = Sender(self.transport), Receiver(self.transport)
        except Exception as e:
            messagebox.showerror('Ошибка генерации', str(e))

    def load(self):
        try:
            self.public, self.private = load_keys()
            self.key_info.set(self._key_description())
            self._log(self.key_log, 'Ключи загружены из keys/public.json и keys/private.json')
        except Exception as e:
            messagebox.showerror('Ошибка загрузки', str(e))

    def reset_workflow(self):
        """Очищает обмен сообщениями, не изменяя уже созданные ключи."""
        for widget in (self.message, self.received, self.sender_log, self.receiver_log):
            self._log(widget, '')
        self.a_entry.delete(0, 'end')
        self.b_entry.delete(0, 'end')
        self.received_hash.set('')
        self.last_signature = self.last_message = self.last_hash = None
        self.pending_message = self.pending_signature = None
        # Очищаем очередь, сохраняя те же открытый и закрытый ключи.
        self.transport = LocalTransport()
        self.sender, self.receiver = Sender(self.transport), Receiver(self.transport)
        self.status.set('Обмен очищен. Текущие ключи сохранены.')
        self.sender_status.set('Обмен очищен. Текущие ключи сохранены.')

    def sign_message(self):
        if self.private is None:
            messagebox.showwarning('Нет ключа', 'Сначала сгенерируйте ключи')
            return
        try:
            msg = self.message.get('1.0','end-1c').encode('utf-8')
            sig, log = self.sender.sign_message(msg, self.private)
            self.pending_message, self.pending_signature = msg, sig
            self._log(self.sender_log, log)
            self.sender_status.set(f'Подпись создана: ({sig.a}, {sig.b}). Нажмите «Отправить».')
        except Exception as e:
            messagebox.showerror('Ошибка подписи', str(e))

    def send_signed(self):
        if self.pending_signature is None or self.pending_message is None:
            messagebox.showwarning('Нет подписи', 'Сначала подпишите сообщение')
            return
        try:
            self.sender.send_signed(self.pending_message, self.pending_signature)
            _, message_hash = hash_bytes(self.pending_message)
            sent_log = ('\n✓ ОТПРАВЛЕНО ПОЛУЧАТЕЛЮ Б:\n'
                        'M, h(M), (a, b)\n'
                        f'h(M) = {message_hash}\n'
                        f'(a, b) = ({self.pending_signature.a}, {self.pending_signature.b})\n')
            self.sender_log.insert('end', sent_log, 'sent')
            self.sender_log.see('end')
            self.sender_status.set(f'Отправлено: подпись ({self.pending_signature.a}, {self.pending_signature.b})')
        except Exception as e:
            messagebox.showerror('Ошибка отправки', str(e))

    def receive_packet(self):
        if self.public is None:
            messagebox.showwarning('Нет ключа', 'Сначала сгенерируйте ключи')
            return
        try:
            received = self.receiver.receive()
            if received is None:
                self.status.set('Нет новых сообщений в локальном транспорте')
                return
            msg, sig, sent_hash = received
            self.last_signature, self.last_message, self.last_hash = sig, msg, sent_hash
            self._log(self.received, msg.decode('utf-8', errors='replace'))
            self.a_entry.delete(0, 'end')
            self.a_entry.insert(0, str(sig.a))
            self.b_entry.delete(0, 'end')
            self.b_entry.insert(0, str(sig.b))
            self.received_hash.set(sent_hash)
            self._log(self.receiver_log, 'ПАКЕТ ПОЛУЧЕН\nНажмите «Проверить», чтобы проверить подпись.\n')
            self.status.set(f'Пакет получен: подпись ({sig.a}, {sig.b}). Можно изменить данные и проверить.')
        except Exception as e:
            self.status.set('Ошибка приёма: ' + str(e))

    def verify_edited(self):
        if self.last_signature is None or self.public is None:
            messagebox.showwarning('Нет подписи', 'Сначала отправьте сообщение')
            return
        try:
            msg = self.received.get('1.0','end-1c').encode('utf-8')
            _, received_hash = hash_bytes(msg)
            if received_hash != self.last_hash:
                log = ('ПРОВЕРКА ЦЕЛОСТНОСТИ СООБЩЕНИЯ\n'
                       f'h(M) = {self.last_hash}  (получен в пакете)\n'
                       f'h′(M′) = {received_hash}\n'
                       'h′(M′) ≠ h(M)\n'
                       'СООБЩЕНИЕ ИЗМЕНЕНО: проверка подписи не выполняется.\n')
                self._log(self.receiver_log, log)
                self.status.set('✗ ХЕШИ НЕ СОВПАЛИ: сообщение отклонено')
                return
            signature = Signature(int(self.a_entry.get()), int(self.b_entry.get()))
            valid, log = verify(msg, signature, self.public)
            log = ('ПРОВЕРКА ЦЕЛОСТНОСТИ СООБЩЕНИЯ\n'
                   f'h(M) = {self.last_hash}  (получен в пакете)\n'
                   f'h′(M) = {received_hash}\n'
                   'h′(M) = h(M): сообщение не изменено, запускаем проверку подписи.\n\n'
                   + log)
            self._log(self.receiver_log, log)
            self.status.set('✓ ПОДПИСЬ ВЕРНА' if valid else '✗ ПОДПИСЬ НЕВЕРНА')
        except ValueError:
            messagebox.showerror('Ошибка подписи', 'a и b должны быть целыми числами')

def main():
    App().mainloop()
