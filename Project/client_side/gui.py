from tkinter import *
import tkinter
from tkinter import filedialog
import customtkinter
from PIL import ImageTk, Image
from client_CDT import *
from AES_functions import *
import hashlib


class ClientGUI(customtkinter.CTk):

    def __init__(self, server_ip, server_port):
        """The function receives the server's (destination) IP address and port number as parameters.
        This function builds a GUI screen object for each of the server's clients."""
        super().__init__()  # Call to __init__ of super class
        # Connect client to server:
        self.client_obj = Client(server_ip, server_port)
        self.client_obj.open_socket()
        self.client_obj.connect_client_to_server()
        self.client_port = self.client_obj.receive_message()  # Receive the client's port number for future usage
        # Build some of the GUI elements:
        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("blue")
        self.geometry("680x850")
        self.frame = customtkinter.CTkFrame(master=self)  # Create the first frame
        self.frame.pack(pady=20, padx=30, fill="both", expand=True)
        img = Image.open(r"C:\Users\NOA\Desktop\CyberProject-CDT\CDT_sign2.png")
        resized_image = img.resize((360, 260), Image.ANTIALIAS)  # Resize the Image using resize method
        self.new_image = ImageTk.PhotoImage(resized_image)
        # Create a default value for the different attributes:
        self.null_pass_warning = None
        self.different_pass_warning = None
        self.nameAlreadyExist_warning = None
        self.null_username_warning = None
        self.userNotExist_warning = None
        self.null_url_warning = None
        self.incorrect_url_warning = None
        self.weakPassword_warning = None
        self.empty_file_warning = None
        self.wrong_fileType_warning = None
        self.susUrl_result_label = None
        self.password_result_label = None
        self.maliciousFile_result_label = None
        self.fernet_obj = fernet_obj_generator(self.client_port)  # Generates a Fernet object for future usage
        self.login_page()  # Build first GUI page

    def rebuild_frame(self, title_name=None):
        """The function receives a page name as a parameter. The page name is set to
        None by default.
        This function is activated by having the client press the buttons 'Home page'/
        'Sign in'/'Login', while entering the correct data before pressing the last two buttons.
        This function destroys the current GUI page frame and builds an empty one with the
        given title, in case one has been supplied."""
        self.frame.destroy()
        if title_name is not None:
            self.title(title_name)
        self.frame = customtkinter.CTkFrame(master=self)
        self.frame.pack(pady=20, padx=30, fill="both", expand=True)

    def end(self):
        """Function doesn't receive any parameters.
        This function is activated by having the client press the buttons exit sign--> X.
        This function creates the application and also completely closes it. In addition,
        it closes the clients connection with the server using other functions."""
        self.mainloop()
        self.client_obj.send_message("end")  # Send final message
        self.client_obj.close_socket()

    def login_page(self):
        """Function doesn't receive any parameters.
        This function is activated when a new client, who wants to use the CDT, is created.
        This function creates the login GUI screen."""
        self.title("Login Page")
        CDT_label = customtkinter.CTkLabel(master=self.frame, text="CDT-Cyber Defense Tool", font=("Ariel", 40, "bold"))
        CDT_label.place(x=80, y=40)
        login_label = customtkinter.CTkLabel(master=self.frame, text="Login Page", font=("Ariel", 25, "bold"))
        login_label.place(x=240, y=100)
        panel = tkinter.Label(self.frame, image=self.new_image, bd=0)  # Add image to the login page
        panel.place(x=130, y=160)
        username_label = customtkinter.CTkLabel(master=self.frame, text="User Name", font=("Ariel", 20, "bold"))
        username_label.place(x=150, y=470)
        pass_label = customtkinter.CTkLabel(master=self.frame, text="Password", font=("Ariel", 20, "bold"))
        pass_label.place(x=150, y=535)
        self.username = StringVar()
        username_entry = customtkinter.CTkEntry(master=self.frame, width=180, textvariable=self.username)
        username_entry.place(x=360, y=470)
        self.user_password = StringVar()
        pass_entry = customtkinter.CTkEntry(master=self.frame, width=180, show='*', textvariable=self.user_password)
        pass_entry.place(x=360, y=535)
        self.login_button = customtkinter.CTkButton(master=self.frame, text="Login", font=("Ariel", 20),
                                                    command=self.check_login_data)
        self.login_button.place(x=255, y=595)
        signup_label = customtkinter.CTkLabel(master=self.frame,
                                              text="Aren't Signed? sign\nup for free to enjoy\neverything we offer",
                                              font=("Ariel", 20, "bold"))
        signup_label.place(x=20, y=700)
        self.signup_button = customtkinter.CTkButton(master=self.frame, text="Sign up", width=20, font=("Ariel", 22),
                                                command=self.signup_page)
        self.signup_button.place(x=230, y=720)

    def check_login_data(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Login'.
        This function verifies the correctness of the entered data by performing checks and
        asking the server to confirm the user's existence. If so, the currently shown page
        will be deleted, and a new Home GUI screen will appear. Otherwise, an error
        message will appear accordingly."""
        self.login_button.configure(state="disabled")
        if self.null_username_warning is not None:
            self.null_username_warning.destroy()
        if self.null_pass_warning is not None:
                self.null_pass_warning.destroy()
        if self.userNotExist_warning is not None:
            self.userNotExist_warning.destroy()
        if len(self.username.get()) == 0:
            self.null_username_warning = customtkinter.CTkLabel(master=self.frame, text="You didn't entered a username- Please try again! ",
                                                             font=("Ariel", 18, "bold"))
            self.null_username_warning.place(x=105, y=630)
        elif len(self.user_password.get()) == 0:
            self.null_pass_warning = customtkinter.CTkLabel(master=self.frame, text="You didn't entered a password- Please try again! ",
                                                             font=("Ariel", 18, "bold"))
            self.null_pass_warning.place(x=100, y=630)
        else:  # Check data with the database
            self.client_obj.send_message("login")  # Client is in the login page
            password_hash = hashlib.md5(self.user_password.get().encode()).hexdigest()
            self.client_obj.send_message(f"{self.username.get()},{password_hash}")
            msg = self.client_obj.receive_message()
            if msg == "true":  # User exists in the database
                self.home_page()
            else:  # User doesn't exist in the database
                self.userNotExist_warning = customtkinter.CTkLabel(master=self.frame, text="User doesn't exist- Please try again! ",
                                                             font=("Ariel", 18, "bold"))
                self.userNotExist_warning.place(x=150, y=630)
        try:
            self.login_button.configure(state="normal")
        except:  # The login frame has been closed
            pass

    def signup_page(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Sign up' in the login page.
        This function creates the sign up GUI screen."""
        self.rebuild_frame("Sign Up Page")
        CDT_label = customtkinter.CTkLabel(master=self.frame, text="CDT-Cyber Defense Tool", font=("Ariel", 40, "bold"))
        CDT_label.place(x=80, y=40)
        login_label = customtkinter.CTkLabel(master=self.frame, text="Sign Up Page", font=("Ariel", 25, "bold"))
        login_label.place(x=240, y=100)
        panel = tkinter.Label(self.frame, image=self.new_image, bd=0)  # Add image to the signup page
        panel.place(x=130, y=160)
        username_label = customtkinter.CTkLabel(master=self.frame, text="User Name", font=("Ariel", 20, "bold"))
        username_label.place(x=120, y=470)
        pass_label = customtkinter.CTkLabel(master=self.frame, text="Password", font=("Ariel", 20, "bold"))
        pass_label.place(x=120, y=535)
        pass_confirm_label = customtkinter.CTkLabel(master=self.frame, text="Re-Enter Password", font=("Ariel", 20, "bold"))
        pass_confirm_label.place(x=120, y=600)
        self.new_username = StringVar()
        username_entry = customtkinter.CTkEntry(master=self.frame, width=180, textvariable=self.new_username)
        username_entry.place(x=360, y=470)
        self.newUser_password = StringVar()
        pass_entry = customtkinter.CTkEntry(master=self.frame, width=180,
                                                 show='*', textvariable=self.newUser_password)
        pass_entry.place(x=360, y=535)
        self.confirm_password = StringVar()
        pass_confirm_entry = customtkinter.CTkEntry(master=self.frame, width=180, show='*',
                                                    textvariable=self.confirm_password)
        pass_confirm_entry.place(x=360, y=600)
        self.signIn_button = customtkinter.CTkButton(master=self.frame, text="Sign in", font=("Ariel", 20), command=self.check_signup_data)
        self.signIn_button.place(x=255, y=650)

    def check_signup_data(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Sign in'.
        This function verifies the correctness of the entered data by performing different
        checks. when the data is confirmed a new user is added to the server's database and
        the currently shown page is deleted, and replaced by the Login page. Otherwise,
        an error message will appear accordingly."""
        self.signIn_button.configure(state="disabled")
        if self.null_username_warning is not None:
            self.null_username_warning.destroy()
        if self.null_pass_warning is not None:
                self.null_pass_warning.destroy()
        if self.different_pass_warning is not None:
            self.different_pass_warning.destroy()
        if self.nameAlreadyExist_warning is not None:
            self.nameAlreadyExist_warning.destroy()
        if self.weakPassword_warning is not None:
            self.weakPassword_warning.destroy()
        if len(self.new_username.get()) == 0:
            self.null_username_warning = customtkinter.CTkLabel(master=self.frame, text=" You didn't entered a username- Please try again! ",
                                                                font=("Ariel", 18, "bold"))
            self.null_username_warning.place(x=105, y=690)
        elif len(self.newUser_password.get()) == 0 or len(self.confirm_password.get()) == 0:
            self.null_pass_warning = customtkinter.CTkLabel(master=self.frame, text=" You didn't entered a password- Please try again! ",
                                                            font=("Ariel", 18, "bold"))
            self.null_pass_warning.place(x=100, y=690)
        elif self.newUser_password.get() != self.confirm_password.get():
            self.different_pass_warning = customtkinter.CTkLabel(master=self.frame, text=" Passwords are different- Please try again! ",
                                                                 font=("Ariel", 18, "bold"))
            self.different_pass_warning.place(x=120, y=690)
        else:
            self.client_obj.send_message("name exists?")  # Client is in the signup page
            self.client_obj.send_message(self.new_username.get())
            if self.client_obj.receive_message() == "false":  # Check if username already exists in db
                self.client_obj.send_message("test password strength")
                encrypted_newUser_password = AES_encrypt(self.newUser_password.get(), self.fernet_obj)
                self.client_obj.send_message(encrypted_newUser_password, False)
                if self.client_obj.receive_message() == "true":  # Check if password is strong enough
                    self.client_obj.send_message("add user")  # add new user to the database
                    new_password_hash = hashlib.md5(self.newUser_password.get().encode()).hexdigest()
                    self.client_obj.send_message(f"{self.new_username.get()},{new_password_hash}")  # Add user to the database
                    self.rebuild_frame()
                    self.login_page()
                else:
                    self.weakPassword_warning = customtkinter.CTkLabel(master=self.frame,
                                                                       text="Your password isn't strong enough-Please try:\n-Making it longer\n-Using capital letters, lowercase letters, numbers, punctuations\n-Ensuring that the numbers & letters arent part of a common series",
                                                                       font=("Ariel", 18, "bold"), justify="left")
                    self.weakPassword_warning.place(x=5, y=690)
            else:
                self.nameAlreadyExist_warning = customtkinter.CTkLabel(master=self.frame,
                                                                       text=" Username is taken- Try entering a different one! ",
                                                                       font=("Ariel", 18, "bold"))
                self.nameAlreadyExist_warning.place(x=100, y=690)
        try:
            self.signIn_button.configure(state="normal")
        except:  # The sign up frame has been closed
            pass

    def home_page(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Login' which is in the login page, while the inserted data is correct.
        This function creates the Home GUI screen."""
        self.rebuild_frame("Home Page")
        CDT_label = customtkinter.CTkLabel(master=self.frame, text="CDT-Cyber Defense Tool", font=("Ariel", 40, "bold"))
        CDT_label.place(x=80, y=40)
        homePage_label = customtkinter.CTkLabel(master=self.frame, text="Home Page", font=("Ariel", 25, "bold"))
        homePage_label.place(x=240, y=100)
        panel = tkinter.Label(self.frame, image=self.new_image, bd=0)  # Add image to the login page
        panel.place(x=130, y=160)
        homeInstructions = customtkinter.CTkLabel(master=self.frame, text="Choose a service you would like to use by pressing its button", font=("Ariel", 20, "bold"))
        homeInstructions.place(x=20, y=470)
        block_vulnerabilities_button = customtkinter.CTkButton(master=self.frame, text="Block\nVulnerabilities",
                                                               font=("Ariel", 20), command=self.block_vulnerabilities_page)
        block_vulnerabilities_button.place(x=80, y=570)
        malicious_url_detector_button = customtkinter.CTkButton(master=self.frame, text="Malicious URL\nDetector",
                                                               font=("Ariel", 20), command=self.malicious_url_detector_page)
        malicious_url_detector_button.place(x=80, y=670)
        password_strength_meter_button = customtkinter.CTkButton(master=self.frame, text="Password Strength\nMeter",
                                                               font=("Ariel", 20), command=self.password_strength_meter_page)
        password_strength_meter_button.place(x=350, y=570)
        malicious_file_detector_button = customtkinter.CTkButton(master=self.frame, text="Malicious File\nDetector",
                                                               font=("Ariel", 20), command=self.malicious_file_detector_page)
        malicious_file_detector_button.place(x=350, y=670)

    def block_vulnerabilities_page(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Block Vulnerabilities' in
        the Home page.
        This function creates the block vulnerabilities GUI screen."""
        self.rebuild_frame("Block Vulnerabilities Page")
        self.homePage_button = customtkinter.CTkButton(master=self.frame, text="Home Page", width=15, command=self.home_page)
        self.homePage_button.place(x=540, y=0)
        CDT_label = customtkinter.CTkLabel(master=self.frame, text="CDT-Cyber Defense Tool", font=("Ariel", 40, "bold"))
        CDT_label.place(x=80, y=40)
        blockVulnerabilitiesPage_label = customtkinter.CTkLabel(master=self.frame, text="Block Vulnerabilities Page",
                                                                font=("Ariel", 25, "bold"))
        blockVulnerabilitiesPage_label.place(x=150, y=100)
        blockVulnerabilitiesInstructions1_label = customtkinter.CTkLabel(master=self.frame, text="This service blocks your computer vulnerabilities in order to\ndefend it from cyber attacks. There are 3 levels of protection:",
                                                                        font=("Ariel", 20, "bold"))
        blockVulnerabilitiesInstructions1_label.place(x=20, y=170)
        basicLevel_label = customtkinter.CTkLabel(master=self.frame, text="Basic: Blocks certain threatening ports that are considered weak and\nexploitable in the cyber world",
                                                  font=("Ariel", 18), justify='left')
        basicLevel_label.place(y=260)
        advancedLevel_label = customtkinter.CTkLabel(master=self.frame, text="Advanced: Updates patches of programs that are installed on your computer\nand blocks certain threatening ports that are considered weak and exploitable in the cyber world",
                                                     font=("Ariel", 18), justify='left')
        advancedLevel_label.place(y=320)
        expertLevel_label = customtkinter.CTkLabel(master=self.frame, text="Expert: Blocks certain threatening ports and any other of your open ports, that\nare considered weak and exploitable in the cyber world. In addition we will\nupdates patches of programs that are installed on your computer",
                                                   font=("Ariel", 18), justify='left')
        expertLevel_label.place(y=380)
        blockVulnerabilitiesInstructions2_label = customtkinter.CTkLabel(master=self.frame, text="Please choose which level\nof protection you would like to\nhave. Note that you can always\ncome back and try a different one",
                                                                        font=("Ariel", 18, "bold"), justify='left')
        blockVulnerabilitiesInstructions2_label.place(x=20, y=480)
        protectionLevel = StringVar()
        self.protectionLevel_combobox = customtkinter.CTkOptionMenu(master=self.frame, values=["Basic", "Advanced", "Expert"],
                                                                    command=self.block_vulnerabilities_func,
                                                                    variable=protectionLevel)
        self.protectionLevel_combobox.place(x=400, y=500)
        self.update_patches_text = Text(master=self.frame, width="56", height="11", font=("Ariel", 14))
        self.update_patches_text.place(x="0", y="580")

    def block_vulnerabilities_func(self, protectionLevel):
        """The function receives a protection level (Basic/Advanced/Expert) as a parameter.
        This function is activated when choosing the option in the combobox which is in
        the block vulnerabilities page.
        This function activates the block vulnerabilities engine using another function and
        outputs the result in the block vulnerabilities GUI screen."""
        self.protectionLevel_combobox.configure(state="disabled")
        self.homePage_button.configure(state="disabled")
        self.update_patches_text.delete(1.0, "end")
        engine_result = self.client_obj.choice1(protectionLevel, self.client_port)
        if type(engine_result[1]) == list:
            for name in engine_result[1]:
                self.update_patches_text.insert(1.0, f"\n{name}")
            self.update_patches_text.insert(1.0, "\nThe patches we failed to update are:")
        self.update_patches_text.insert(1.0, f"The amount of vulnerable ports we blocked: {engine_result[0]}")
        try:
            self.protectionLevel_combobox.configure(state="normal")
            self.homePage_button.configure(state="normal")
        except:  # The Block vulnerabilities frame has been closed
            pass

    def malicious_url_detector_page(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Malicious URL Detector' in
        the Home page.
        This function creates the malicious URL detector GUI screen."""
        self.rebuild_frame("Malicious URL Detector Page")
        self.homePage_button = customtkinter.CTkButton(master=self.frame, text="Home Page", width=15, command=self.home_page)
        self.homePage_button.place(x=540, y=0)
        CDT_label = customtkinter.CTkLabel(master=self.frame, text="CDT-Cyber Defense Tool", font=("Ariel", 40, "bold"))
        CDT_label.place(x=80, y=40)
        maliciousUrlDetectorPage_label = customtkinter.CTkLabel(master=self.frame, text="Malicious URL Detector Page", font=("Ariel", 25, "bold"))
        maliciousUrlDetectorPage_label.place(x=150, y=100)
        maliciousUrlDetectorInstructions1_label = customtkinter.CTkLabel(master=self.frame, text="Enter any URL and we will check if its malicious or benign:",
                                                                        font=("Ariel", 20, "bold"))
        maliciousUrlDetectorInstructions1_label.place(x=30, y=200)
        self.sus_url = StringVar()
        url_entry = customtkinter.CTkEntry(master=self.frame, width=500, textvariable=self.sus_url)
        url_entry.place(x=60, y=270)
        self.execute_susUrl_button = customtkinter.CTkButton(master=self.frame, text="Execute",
                                                               font=("Ariel", 20), command=self.malicious_url_detector_func)
        self.execute_susUrl_button.place(x=240, y=320)

    def malicious_url_detector_func(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Execute' in the malicious
        URL detector page.
        This function first ensures that the inserted URL is in the correct format, if so
        then the malicious URL detector engine is activated using another function and its
        result is shown in the malicious URL detector GUI screen. If not, a corresponding
        error will be displayed."""
        self.execute_susUrl_button.configure(state="disabled")
        self.homePage_button.configure(state="disabled")
        if self.null_url_warning is not None:
            self.null_url_warning.destroy()
        if self.incorrect_url_warning is not None:
            self.incorrect_url_warning.destroy()
        if self.susUrl_result_label is not None:
            self.susUrl_result_label.destroy()
        if len(self.sus_url.get()) == 0:
            self.null_url_warning = customtkinter.CTkLabel(master=self.frame, text=" You didn't entered a URL- Please try again! ",
                                                             font=("Ariel", 18, "bold"))
            self.null_url_warning.place(x=120, y=365)
        elif not self.sus_url.get().startswith("https://") and not self.sus_url.get().startswith("http://"):
            self.incorrect_url_warning = customtkinter.CTkLabel(master=self.frame, text="incorrect URL- Please enter a full URL (including https:// or http://)",
                                                             font=("Ariel", 18, "bold"))
            self.incorrect_url_warning.place(x=50, y=365)
        else:
            self.client_obj.send_message("choice2")
            self.client_obj.send_message(self.sus_url.get())
            engine_result = self.client_obj.receive_message()  # Activate engine for the result
            self.susUrl_result_label = customtkinter.CTkLabel(master=self.frame, text=f"{engine_result}",
                                                         font=("Ariel", 18, "bold"), justify="left")
            self.susUrl_result_label.place(y=365)
        try:
            self.execute_susUrl_button.configure(state="normal")
            self.homePage_button.configure(state="normal")
        except:  # The malicious URL detector frame has been closed
            pass

    def password_strength_meter_page(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Password Strength Meter' in
        the Home page.
        This function creates the password strength meter GUI screen."""
        self.rebuild_frame("Password Strength Meter Page")
        self.homePage_button = customtkinter.CTkButton(master=self.frame, text="Home Page", width=15, command=self.home_page)
        self.homePage_button.place(x=540, y=0)
        CDT_label = customtkinter.CTkLabel(master=self.frame, text="CDT-Cyber Defense Tool", font=("Ariel", 40, "bold"))
        CDT_label.place(x=80, y=40)
        passwordStrengthMeterPage_label = customtkinter.CTkLabel(master=self.frame, text="Password Strength Meter Page", font=("Ariel", 25, "bold"))
        passwordStrengthMeterPage_label.place(x=120, y=100)
        passwordStrengthMeterInstructions_label = customtkinter.CTkLabel(master=self.frame, text="Enter any password and we will check its strength.\nStrength means how hard to guess this password is",
                                                                        font=("Ariel", 20, "bold"),
                                                                        justify="left")
        passwordStrengthMeterInstructions_label.place(x=30, y=230)
        self.passwordTest = StringVar()
        passwordTest_entry = customtkinter.CTkEntry(master=self.frame, width=300, textvariable=self.passwordTest)
        passwordTest_entry.place(x=160, y=310)
        self.execute_susUrl_button = customtkinter.CTkButton(master=self.frame, text="Execute",
                                                        font=("Ariel", 20), command=self.password_strength_meter_func)
        self.execute_susUrl_button.place(x=240, y=360)
        passwordStrengthRecs_label = customtkinter.CTkLabel(master=self.frame, text="We recommend your password to:\n\n-Be at least 8 letters long\n-Contain both capital letters and lowercase\n-Try not to use your first/last name\n-Contain different numbers\n-Make sure that the numbers/letters aren't part of a common series\n-Contain punctuations",
                                                            font=("Ariel", 19, "bold"), justify="left")
        passwordStrengthRecs_label.place(y=550)

    def password_strength_meter_func(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Execute' in the password
        strength meter page.
        This function first ensures that a password has been entered, if so then the password
        is encrypted in the AES algorithm, then the password strength meter engine is
        activated, using another function, and its result is shown in the password
        strength meter GUI screen. If not, a null error will be displayed."""
        self.execute_susUrl_button.configure(state="disabled")
        self.homePage_button.configure(state="disabled")
        if self.password_result_label is not None:
            self.password_result_label.destroy()
        if self.null_pass_warning is not None:
                self.null_pass_warning.destroy()
        if len(self.passwordTest.get()) == 0:
            self.null_pass_warning = customtkinter.CTkLabel(master=self.frame, text="You didn't any entered a password- Please try again! ",
                                                             font=("Ariel", 18, "bold"))
            self.null_pass_warning.place(x=85, y=400)
        else:
            self.client_obj.send_message("choice3")
            encrypted_engine_password = AES_encrypt(self.passwordTest.get(), self.fernet_obj)
            self.client_obj.send_message(encrypted_engine_password, False)
            engine_result = self.client_obj.receive_message()
            self.password_result_label = customtkinter.CTkLabel(master=self.frame, text=f"{engine_result}",
                                                         font=("Ariel", 18, "bold"), justify="left")
            self.password_result_label.place(y=415)
        try:
            self.execute_susUrl_button.configure(state="normal")
            self.homePage_button.configure(state="normal")
        except:  # The password strength meter frame has been closed
            pass

    def malicious_file_detector_page(self):
        """Function doesn't receive any parameters.
        This function is activated when pressing the button 'Malicious File Detector' in
        the Home page.
        This function creates the malicious file detector GUI screen."""
        self.rebuild_frame("Malicious File Detector Page")
        self.homePage_button = customtkinter.CTkButton(master=self.frame, text="Home Page", width=15, command=self.home_page)
        self.homePage_button.place(x=540, y=0)
        CDT_label = customtkinter.CTkLabel(master=self.frame, text="CDT-Cyber Defense Tool", font=("Ariel", 40, "bold"))
        CDT_label.place(x=80, y=40)
        maliciousFileDetectorPage_label = customtkinter.CTkLabel(master=self.frame, text="Malicious File Detector Page", font=("Ariel", 25, "bold"))
        maliciousFileDetectorPage_label.place(x=140, y=100)
        maliciousFileDetectorInstructions_label = customtkinter.CTkLabel(master=self.frame, text="Upload an executable (exe file) file and we will check if the\nfile is malicious",
                                                                        font=("Ariel", 20, "bold"),
                                                                        justify="left")
        maliciousFileDetectorInstructions_label.place(y=200)
        self.upload_file_button = customtkinter.CTkButton(self.frame, text="Upload File", font=("Ariel", 20, "bold"),
                                                          command=self.malicious_file_detector_func)
        self.upload_file_button.place(x=270, y=260)

    def malicious_file_detector_func(self):
        """The Function doesn't receive any parameters.
        This function is activated when pressing the button 'Upload File' in the malicious
        file detector page.
        This function first checks the uploaded and displays a message if it failed the
        checks. Then the file is sent to the server, using a different function, where the
        malicious file detector engine is activated. Finally, the engine result is shown in
        the malicious file detector GUI screen."""
        self.upload_file_button.configure(state="disabled")
        self.homePage_button.configure(state="disabled")
        if self.empty_file_warning is not None:
            self.empty_file_warning.destroy()
        if self.wrong_fileType_warning is not None:
            self.wrong_fileType_warning.destroy()
        if self.maliciousFile_result_label is not None:
            self.maliciousFile_result_label.destroy()
        file_path = filedialog.askopenfilename()
        file = open(file_path, "rb")
        file_content = file.read()
        if not file_content:  # File is empty
            self.empty_file_warning = customtkinter.CTkLabel(master=self.frame, text="You have uploaded an empty file- Please upload a different file!",
                                                             font=("Ariel", 18, "bold"))
            self.empty_file_warning.place(x=30, y=320)
        elif not file_path.endswith('.exe'):  # File doesn't end with .exe
            self.wrong_fileType_warning = customtkinter.CTkLabel(master=self.frame, text="The file you uploaded isn't executable (exe)- Please\nupload a different file!",
                                                             font=("Ariel", 18, "bold"), justify="left")
            self.wrong_fileType_warning.place(x=10, y=320)
        else:
            self.client_obj.send_message("choice4")
            self.client_obj.send_file(file_path)
            engine_result = self.client_obj.receive_message()
            self.maliciousFile_result_label = customtkinter.CTkLabel(master=self.frame, text=f"{engine_result}",
                                                                font=("Ariel", 18, "bold"),
                                                                justify="left")
            self.maliciousFile_result_label.place(y=370)
        try:
            self.upload_file_button.configure(state="normal")
            self.homePage_button.configure(state="normal")
        except:  # The malicious file detector frame has been closed
            pass


client2 = ClientGUI('192.168.1.48', 4444)
client2.end()

client3 = ClientGUI('192.168.1.48', 4444)
client3.end()
