import tkinter as tk
from tkinter import messagebox
from zxcvbn import zxcvbn
from datetime import timedelta
from cryptography.fernet import Fernet
import os

ENCRYPTION_KEY = b'YOUR_ENCRYPTION_KEY_HERE'

def save_and_encrypt_password():
    def save_password():
        # Get password from entry field
        password = password_entry.get()

        # Password Strength Checker
        result = zxcvbn(password)
        score = result["score"]
        strength = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        password_strength = strength[score]
        password_strength_label.config(text="Password strength: " + password_strength)

        # Estimated Time to Crack Password
        crack_time_seconds = int(result["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"])
        cracking_time = timedelta(seconds=crack_time_seconds)
        cracking_time_label.config(text="Estimated time to crack the password: " + str(cracking_time))

        # Prompt user to save the password
        save_password = messagebox.askyesno("Save Password", "Do you want to save this password?")

        if save_password:
            # Prompt user for website, email, and username
            website = website_entry.get()
            email = email_entry.get()
            username = username_entry.get()

            # Encrypt the password
            cipher_suite = Fernet(ENCRYPTION_KEY)
            encrypted_password = cipher_suite.encrypt(password.encode()).decode()

            # Save the password details to the passwords.txt file
            with open("passwords.txt", "a") as file:
                file.write(f"Website: {website}\n")
                file.write(f"Email: {email}\n")
                file.write(f"Username: {username}\n")
                file.write(f"Encrypted Password: {encrypted_password}\n")
                file.write("--------------------\n")

            messagebox.showinfo("Success", "Password saved and encrypted successfully!")
            save_password_window.destroy()

    save_password_window = tk.Toplevel()
    save_password_window.title("Save Password")

    website_label = tk.Label(save_password_window, text="Website:")
    website_label.pack()
    website_entry = tk.Entry(save_password_window)
    website_entry.pack()

    email_label = tk.Label(save_password_window, text="Email:")
    email_label.pack()
    email_entry = tk.Entry(save_password_window)
    email_entry.pack()

    username_label = tk.Label(save_password_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(save_password_window)
    username_entry.pack()

    password_label = tk.Label(save_password_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(save_password_window, show="*")
    password_entry.pack()

    save_button = tk.Button(save_password_window, text="Save", command=save_password)
    save_button.pack()

    password_strength_label = tk.Label(save_password_window, text="")
    password_strength_label.pack()

    cracking_time_label = tk.Label(save_password_window, text="")
    cracking_time_label.pack()

def decrypt_passwords():
    def decrypt_password():
        # Get selected password index
        selected_index = password_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("No Selection", "Please select a password.")
            return
        selected_index = selected_index[0]

        # Get the selected password details
        selected_password = passwords[selected_index]
        encrypted_password = selected_password.split("\n")[-2].split(": ")[1]

        # Decrypt the selected password
        cipher_suite = Fernet(ENCRYPTION_KEY)
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()

        # Show the decrypted password
        messagebox.showinfo("Decrypted Password", f"Decrypted Password: {decrypted_password}")

    decrypt_password_window = tk.Toplevel()
    decrypt_password_window.title("Decrypt Passwords")

    password_listbox = tk.Listbox(decrypt_password_window, width=50)
    password_listbox.pack()

    # Load the encrypted passwords from the passwords.txt file
    try:
        with open("passwords.txt", "r") as file:
            passwords = file.read().split("--------------------\n")
    except FileNotFoundError:
        messagebox.showerror("Error", "No passwords found. Please save some passwords first.")
        decrypt_password_window.destroy()
        return

    # Display the website and username options
    for password in passwords:
        if password.strip():
            website = password.split("\n")[0].split(": ")[1]
            username = password.split("\n")[2].split(": ")[1]
            password_listbox.insert(tk.END, f"{website} - {username}")

    decrypt_button = tk.Button(decrypt_password_window, text="Decrypt", command=decrypt_password)
    decrypt_button.pack()

def delete_passwords():
    def delete_password():
        # Get selected password index
        selected_index = password_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("No Selection", "Please select a password.")
            return
        selected_index = selected_index[0]

        # Get the selected password details
        selected_password = passwords[selected_index]
        encrypted_password = selected_password.split("\n")[-2].split(": ")[1]

        # Delete the selected password
        passwords.remove(selected_password)

        # Update the passwords.txt file
        with open("passwords.txt", "w") as file:
            file.write("--------------------\n".join(passwords))

        messagebox.showinfo("Success", "Password deleted successfully!")
        delete_password_window.destroy()

    delete_password_window = tk.Toplevel()
    delete_password_window.title("Delete Passwords")

    password_listbox = tk.Listbox(delete_password_window, width=50)
    password_listbox.pack()

    # Load the encrypted passwords from the passwords.txt file
    try:
        with open("passwords.txt", "r") as file:
            passwords = file.read().split("--------------------\n")
    except FileNotFoundError:
        messagebox.showerror("Error", "No passwords found. Please save some passwords first.")
        delete_password_window.destroy()
        return

    # Display the website and username options
    for password in passwords:
        if password.strip():
            website = password.split("\n")[0].split(": ")[1]
            username = password.split("\n")[2].split(": ")[1]
            password_listbox.insert(tk.END, f"{website} - {username}")

    delete_button = tk.Button(delete_password_window, text="Delete", command=delete_password)
    delete_button.pack()

def show_encryption_key():
    def check_pin():
        entered_pin = pin_entry.get()
        if entered_pin == "YOUR_PIN_HERE":
            messagebox.showinfo("Encryption Key", f"Encryption Key: {ENCRYPTION_KEY}")
        else:
            messagebox.showerror("Error", "Incorrect PIN. Encryption key cannot be accessed.")
        pin_window.destroy()

    pin_window = tk.Toplevel()
    pin_window.title("Enter PIN")

    pin_label = tk.Label(pin_window, text="Enter your secret PIN:")
    pin_label.pack()

    pin_entry = tk.Entry(pin_window, show="*")
    pin_entry.pack()

    submit_button = tk.Button(pin_window, text="Submit", command=check_pin)
    submit_button.pack()

def main_menu():
    main_window = tk.Tk()
    main_window.title("Password Manager")

    save_button = tk.Button(main_window, text="Save Password", command=save_and_encrypt_password)
    save_button.pack()

    decrypt_button = tk.Button(main_window, text="Decrypt Passwords", command=decrypt_passwords)
    decrypt_button.pack()

    delete_button = tk.Button(main_window, text="Delete Passwords", command=delete_passwords)
    delete_button.pack()

    show_key_button = tk.Button(main_window, text="Show Encryption Key", command=show_encryption_key)
    show_key_button.pack()

    exit_button = tk.Button(main_window, text="Exit", command=main_window.quit)
    exit_button.pack()

    main_window.mainloop()

if __name__ == "__main__":
    # Check if the passwords.txt file exists, if not create an empty one
    if not os.path.exists("passwords.txt"):
        with open("passwords.txt", "w"):
            pass

    main_menu()
