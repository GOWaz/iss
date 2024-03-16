import customtkinter

customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('dark-blue')


class GUI:
    def __init__(self) -> None:
        self.root = customtkinter.CTk()
        self.root.geometry(f"{400}x{400}")

        self.login()
        self.signup()
        self.enterInfo()
        self.mainPage()

    def login(self):
        # LOGIN
        self.loginFrame = customtkinter.CTkFrame(master=self.root)
        self.loginFrame.pack(pady=20, padx=60, fill='both', expand=True)

        self.label = customtkinter.CTkLabel(master=self.loginFrame, text='login')
        self.label.pack(pady=12, padx=10)

        self.entry1 = customtkinter.CTkEntry(master=self.loginFrame, placeholder_text='Username')
        self.entry1.pack(pady=12, padx=10)
        self.entry2 = customtkinter.CTkEntry(master=self.loginFrame, placeholder_text='Password', show='*')
        self.entry2.pack(pady=12, padx=10)

        self.button1 = customtkinter.CTkButton(master=self.loginFrame, text='login', command=self.tick1)
        self.button1.pack(pady=12, padx=10)
        self.button2 = customtkinter.CTkButton(master=self.loginFrame, text='signup', command=self.tick2)
        self.button2.pack(pady=12, padx=10)

    def signup(self):
        # SIGNUP
        self.signupFrame = customtkinter.CTkFrame(master=self.root)
        # self.signupFrame.pack(pady=20,padx=60 , fill='both',expand=True)

        self.label = customtkinter.CTkLabel(master=self.signupFrame, text='Signup')
        self.label.pack(pady=12, padx=10)

        self.entry1 = customtkinter.CTkEntry(master=self.signupFrame, placeholder_text='Username')
        self.entry1.pack(pady=12, padx=10)
        self.entry2 = customtkinter.CTkEntry(master=self.signupFrame, placeholder_text='Password', show='*')
        self.entry2.pack(pady=12, padx=10)

        self.optionmenu = customtkinter.CTkOptionMenu(self.signupFrame, values=["Student", "Professor"])
        self.optionmenu.pack(pady=10, padx=10)
        self.optionmenu.set("Student")

        self.button = customtkinter.CTkButton(master=self.signupFrame, text='signup', command=self.tick2)
        self.button.pack(pady=12, padx=10)

    def enterInfo(self):
        # ENTER INFO 
        self.enterInfoFrame = customtkinter.CTkFrame(master=self.root)
        # self.frame2.pack(pady=20,padx=60 , fill='both',expand=True)

        self.label = customtkinter.CTkLabel(master=self.enterInfoFrame, text='Student info')
        self.label.pack(pady=12, padx=10)

        self.entry1 = customtkinter.CTkEntry(master=self.enterInfoFrame, placeholder_text='Phone number')
        self.entry1.pack(pady=12, padx=10)
        self.entry2 = customtkinter.CTkEntry(master=self.enterInfoFrame, placeholder_text='residence')
        self.entry2.pack(pady=12, padx=10)

        self.button = customtkinter.CTkButton(master=self.enterInfoFrame, text='Submit', command=self.tick3)
        self.button.pack(pady=12, padx=10)

    def mainPage(self):
        self.mainPageFrame = customtkinter.CTkFrame(master=self.root)

        self.entry = customtkinter.CTkEntry(master=self.mainPageFrame, placeholder_text='message')
        self.entry.pack(pady=12, padx=10)

        self.button = customtkinter.CTkButton(master=self.mainPageFrame, text='Submit', command=self.tick3)
        self.button.pack(pady=12, padx=10)

    def tick1(self):
        self.loginFrame.pack_forget()
        self.enterInfoFrame.pack(pady=20, padx=60, fill='both', expand=True)
        print('test')

    def tick2(self):
        self.loginFrame.pack_forget()
        self.signupFrame.pack(pady=20, padx=60, fill='both', expand=True)
        print('test')

    def tick3(self):
        self.enterInfoFrame.pack_forget()
        self.mainPageFrame.pack(pady=20, padx=60, fill='both', expand=True)
        print('test')


if __name__ == "__main__":
    app = GUI()
    app.root.mainloop()
