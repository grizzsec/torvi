import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import tika
from tika import parser
import PyPDF2
import fitz
from docx import Document
import olefile
from PIL import Image
import imagehash
import pyclamd
import platform
import time
import hashlib

tika.initVM()

class TorviMetadataAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Torvi - Metadata Analyzer")
        self.root.geometry("800x600")
        self.root.iconbitmap("torvi_icon.ico")
        self.create_widgets()
        self.version = "1.0"

    def create_widgets(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Custom.TButton", foreground="white", background="#0078d4", font=("Arial", 12, "bold"))
        self.style.configure("Custom.TLabel", font=("Arial", 12))

        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Seleccionar archivo", command=self.select_file)
        file_menu.add_command(label="Escanear archivo", command=self.scan_file)
        file_menu.add_command(label="Guardar resultado", command=self.save_result)
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.root.quit)
        menubar.add_cascade(label="Archivo", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Tema claro", command=lambda: self.change_theme("clam"))
        view_menu.add_command(label="Tema oscuro", command=lambda: self.change_theme("default"))
        menubar.add_cascade(label="Ver", menu=view_menu)

        self.notebook = ttk.Notebook(self.root, style="Custom.TNotebook")
        self.notebook.pack(expand=True, fill="both")

        self.metadata_tab = ttk.Frame(self.notebook)
        self.virus_scan_tab = ttk.Frame(self.notebook)
        self.system_info_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.metadata_tab, text="Metadatos")
        self.notebook.add(self.virus_scan_tab, text="Escaneo de Virus")
        self.notebook.add(self.system_info_tab, text="Información del Sistema")

        self.init_metadata_tab()
        self.init_virus_scan_tab()
        self.init_system_info_tab()

        self.version_label = ttk.Label(self.root, text=f"Versión {self.version}", font=("Arial", 10))
        self.version_label.pack(side=tk.BOTTOM, padx=5, pady=5, anchor=tk.SE)

    def init_metadata_tab(self):
        self.metadata_frame = ttk.Frame(self.metadata_tab)
        self.metadata_frame.pack(padx=10, pady=10)

        self.result_text = tk.Text(self.metadata_frame, wrap=tk.WORD, width=80, height=15)
        self.result_text.pack(side=tk.LEFT, padx=5, pady=5, fill="both", expand=True)

        self.scrollbar = ttk.Scrollbar(self.metadata_frame, command=self.result_text.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.config(yscrollcommand=self.scrollbar.set)

        self.open_file_button = ttk.Button(self.metadata_tab, text="Abrir archivo", command=self.open_file)
        self.open_file_button.pack(pady=5)

        self.duplicate_files_button = ttk.Button(self.metadata_tab, text="Buscar duplicados", command=self.find_duplicate_files)
        self.duplicate_files_button.pack(pady=5)

        self.selected_file_label = ttk.Label(self.metadata_tab, text="", font=("Arial", 12))
        self.selected_file_label.pack(pady=5)

        self.hash_button = ttk.Button(self.metadata_tab, text="Calcular hash", command=self.calculate_hash)
        self.hash_button.pack(pady=5)

    def init_virus_scan_tab(self):
        self.virus_result_label = ttk.Label(self.virus_scan_tab, text="", font=("Arial", 12, "bold"))
        self.virus_result_label.pack(pady=10)

        self.progress_bar = ttk.Progressbar(self.virus_scan_tab, orient="horizontal", length=500, mode="determinate")
        self.progress_bar.pack(pady=10)

    def init_system_info_tab(self):
        self.system_info_text = tk.Text(self.system_info_tab, wrap=tk.WORD, width=80, height=15, font=("Courier New", 12))
        self.system_info_text.pack(padx=10, pady=10, fill="both", expand=True)
        self.system_info_text.insert(tk.END, "Información del Sistema:\n")
        self.system_info_text.insert(tk.END, f"Plataforma: {platform.platform()}\n")
        self.system_info_text.insert(tk.END, f"Procesador: {platform.processor()}\n")
        self.system_info_text.insert(tk.END, f"Arquitectura: {platform.machine()}\n")
        self.system_info_text.insert(tk.END, f"Sistema Operativo: {platform.system()} {platform.release()}\n")
        self.system_info_text.insert(tk.END, f"Memoria RAM: {self.get_memory_info()}\n")

    def get_memory_info(self):
        try:
            import psutil
            virtual_memory = psutil.virtual_memory()
            return f"Total: {self.convert_bytes(virtual_memory.total)}, Disponible: {self.convert_bytes(virtual_memory.available)}"
        except ImportError:
            return "No disponible (Instale la biblioteca 'psutil' para obtener información de memoria)"

    def convert_bytes(self, num):
        for x in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return "%3.1f %s" % (num, x)
            num /= 1024.0

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)

    def select_file(self):
        self.file_path = filedialog.askopenfilename(initialdir="/", title="Seleccionar archivo",
                                                    filetypes=(("Archivos compatibles", "*.pdf;*.docx;*.doc;*.xls;*.xlsx;*.ppt;*.pptx;*.jpg;*.png;*.svg;*.mp3;*.flac;*.zip"),
                                                               ("Todos los archivos", "*.*")))
        if self.file_path:
            self.result_text.delete('1.0', tk.END)
            self.selected_file_label.config(text=f"Archivo seleccionado: {self.file_path}")
            self.calculate_hash()

    def calculate_hash(self):
        if hasattr(self, 'file_path'):
            file_hash = self.calculate_sha256_hash(self.file_path)
            self.result_text.insert(tk.END, f"\nSHA-256 Hash del archivo:\n{file_hash}\n\n")

    def scan_file(self):
        self.result_text.delete('1.0', tk.END)
        self.virus_result_label.config(text="")
        if not hasattr(self, 'file_path'):
            self.result_text.insert(tk.END, "Por favor, selecciona un archivo antes de escanear.")
            return

        self.progress_bar["value"] = 0
        self.root.update_idletasks()

        virus_found = self.check_virus_clamav(self.file_path)
        if virus_found:
            self.virus_result_label.config(text="¡Virus o malware detectado en el archivo!", foreground="red")
        else:
            self.virus_result_label.config(text="El archivo está limpio, no se encontraron virus ni malware.", foreground="green")

        # Delay to make the progress bar visible before completing the scan
        time.sleep(0.5)
        self.progress_bar["value"] = 100

    def calculate_sha256_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def check_virus_clamav(self, file_path):
        try:
            cd = pyclamd.ClamdUnixSocket()
            scan_result = cd.scan_file(file_path)
            if scan_result[file_path][0] == 'FOUND':
                return True
            else:
                return False
        except pyclamd.ConnectionError:
            self.result_text.insert(tk.END, "No se pudo conectar al demonio ClamAV. Asegúrate de que esté en funcionamiento.")
            return False

    def find_duplicate_files(self):
        if not hasattr(self, 'file_path'):
            self.result_text.insert(tk.END, "Por favor, selecciona un archivo antes de buscar duplicados.")
            return

        current_directory = os.path.dirname(self.file_path)
        all_files = [f for f in os.listdir(current_directory) if os.path.isfile(os.path.join(current_directory, f))]

        file_hash = self.calculate_sha256_hash(self.file_path)
        duplicate_files = []

        for file_name in all_files:
            if file_name != os.path.basename(self.file_path):
                file_path = os.path.join(current_directory, file_name)
                if file_hash == self.calculate_sha256_hash(file_path):
                    duplicate_files.append(file_path)

        if duplicate_files:
            self.result_text.insert(tk.END, "Archivos duplicados encontrados:\n")
            for duplicate_file in duplicate_files:
                self.result_text.insert(tk.END, f"{duplicate_file}\n")
        else:
            self.result_text.insert(tk.END, "No se encontraron archivos duplicados en el directorio.")

    def open_file(self):
        if hasattr(self, 'file_path'):
            try:
                os.startfile(self.file_path)  # For Windows
            except AttributeError:
                import subprocess
                subprocess.Popen(["xdg-open", self.file_path])  # For Linux

    def save_result(self):
        if hasattr(self, 'file_path'):
            with filedialog.asksaveasfile(defaultextension=".txt", filetypes=(("Archivo de texto", "*.txt"),)) as f:
                if f is None:
                    return
                text_to_save = self.result_text.get("1.0", tk.END)
                f.write(text_to_save)

if __name__ == "__main__":
    root = tk.Tk()
    app = TorviMetadataAnalyzer(root)
    root.mainloop()
