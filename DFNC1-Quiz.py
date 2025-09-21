#!/usr/bin/env python3
# DFNC1 - Kali Linux Cyber Security Quiz
import tkinter as tk
from tkinter import messagebox

class DFNC1Quiz:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("DFNC1 - Kali Linux Cyber Security Quiz")
        self.window.geometry("900x700")
        self.window.configure(bg="#1a1a2e")

        self.levels = ["Beginner", "Intermediate", "Advanced"]
        self.current_level = 0
        self.current_question = 0
        self.score = 0
        self.time_left = 0
        self.timer = None
        self.quiz_active = False

        self.questions = self.load_questions()
        self.setup_ui()

    def load_questions(self):
        return {
            "Beginner": [
                {"question": "Default username and password for Kali Linux?", "options":["root:toor","admin:admin","kali:kali","user:user"], "answer":"root:toor"},
                {"question": "Command to check current directory?", "options":["pwd","ls","cd","dir"], "answer":"pwd"},
                {"question": "What does chmod do?", "options":["Change file permissions","Change ownership","Change content","Change name"], "answer":"Change file permissions"},
                {"question": "Tool for network scanning?", "options":["Nmap","Metasploit","Wireshark","John the Ripper"], "answer":"Nmap"},
                {"question": "Purpose of firewall?", "options":["Monitor and control network traffic","Encrypt data","Store passwords","Create backups"], "answer":"Monitor and control network traffic"},
                {"question": "Command to list files?", "options":["ls","dir","list","show"], "answer":"ls"},
                {"question": "Protocol for secure web browsing?", "options":["HTTPS","HTTP","FTP","SMTP"], "answer":"HTTPS"},
                {"question": "Purpose of encryption?", "options":["Protect data confidentiality","Increase internet speed","Compress files","Organize data"], "answer":"Protect data confidentiality"},
                {"question": "Command to change file permissions?", "options":["chmod","chown","perm","setmod"], "answer":"chmod"},
                {"question": "Common method for password attacks?", "options":["Brute force","Firewall","Encryption","Hashing"], "answer":"Brute force"},
                {"question": "VPN stands for?", "options":["Virtual Private Network","Virtual Public Network","Verified Private Network","Virtual Protection Network"], "answer":"Virtual Private Network"},
                {"question": "Tool for password cracking?", "options":["John the Ripper","Nmap","Wireshark","Metasploit"], "answer":"John the Ripper"},
                {"question": "What is phishing?", "options":["Fraudulent attempt to obtain sensitive info","Encryption type","Network protocol","Linux command"], "answer":"Fraudulent attempt to obtain sensitive info"},
                {"question": "Purpose of antivirus software?", "options":["Detect and remove malware","Encrypt files","Monitor network traffic","Create backups"], "answer":"Detect and remove malware"},
                {"question": "Default port for HTTPS?", "options":["443","80","21","25"], "answer":"443"},
                {"question": "Two-factor authentication is?", "options":["Two methods to verify identity","Using two passwords","Authenticate on two devices","Two user accounts"], "answer":"Two methods to verify identity"},
                {"question": "SSH stands for?", "options":["Secure Shell","Secure Socket Hypertext","System Security Handler","Secure Service Host"], "answer":"Secure Shell"},
                {"question": "Command to display network connections?", "options":["netstat","ifconfig","ping","traceroute"], "answer":"netstat"},
                {"question": "Vulnerability in cybersecurity?", "options":["Weakness that can be exploited","Malware type","Security protocol","Encryption algorithm"], "answer":"Weakness that can be exploited"},
                {"question": "Purpose of proxy server?", "options":["Act as intermediary between client/server","Encrypt data","Store passwords","Scan for viruses"], "answer":"Act as intermediary between client/server"},
                {"question": "Tool for packet analysis?", "options":["Wireshark","Nmap","Metasploit","John the Ripper"], "answer":"Wireshark"},
                {"question": "Social engineering is?", "options":["Manipulating people to disclose info","Engineering social media","Designing social networks","Creating social media content"], "answer":"Manipulating people to disclose info"},
                {"question": "DDoS stands for?", "options":["Distributed Denial of Service","Direct Denial of Service","Data Destruction of Service","Digital Denial of Service"], "answer":"Distributed Denial of Service"},
                {"question": "Command to change file ownership?", "options":["chown","chmod","own","setown"], "answer":"chown"},
                {"question": "Malware is?", "options":["Malicious software","Security protocol","Firewall type","Encryption method"], "answer":"Malicious software"}
            ],
            "Intermediate": [
                {"question": "Difference between TCP and UDP?", "options":["TCP connection-oriented, UDP connectionless","TCP faster","UDP error correction","UDP web browsing"], "answer":"TCP connection-oriented, UDP connectionless"},
                {"question": "What is SQL injection?", "options":["Inject malicious SQL code","Steal credentials","Corrupt databases","Encrypt databases"], "answer":"Inject malicious SQL code"},
                {"question": "Purpose of Metasploit?", "options":["Developing/executing exploit code","Network monitoring","Firewall configuration","Data encryption"], "answer":"Developing/executing exploit code"},
                {"question": "Man-in-the-middle attack is?", "options":["Intercepting communication","Stealing devices","Breaking into data center","Creating fake websites"], "answer":"Intercepting communication"},
                {"question": "Purpose of Wireshark?", "options":["Network protocol analysis","Password cracking","Vulnerability scanning","Web testing"], "answer":"Network protocol analysis"},
                {"question": "Rainbow table attack?", "options":["Using precomputed tables to reverse hashes","Colorful password tables","Rainbow packets","Display color vulnerability"], "answer":"Using precomputed tables to reverse hashes"},
                {"question": "Cross-site scripting (XSS)?", "options":["Inject malicious scripts into webpages","Hack across websites","Web scripting","SQL injection type"], "answer":"Inject malicious scripts into webpages"},
                {"question": "Purpose of Burp Suite?", "options":["Web app security testing","Network scanning","Password cracking","Vulnerability assessment"], "answer":"Web app security testing"},
                {"question": "Buffer overflow vulnerability?", "options":["Writing more data to buffer than it can hold","Overflow network buffer","Create buffer zones","Flush buffer contents"], "answer":"Writing more data to buffer than it can hold"},
                {"question": "Difference between hashing and encryption?", "options":["Hashing is one-way, encryption reversible","Hashing reversible, encryption one-way","Hashing faster than encryption","Encryption passwords, hashing data"], "answer":"Hashing is one-way, encryption reversible"},
                {"question": "What is a reverse shell?", "options":["Shell session from target to attacker","Shell working in reverse","Secure shell connection","Firewall type"], "answer":"Shell session from target to attacker"},
                {"question": "DNS spoofing is?", "options":["Corrupt DNS cache to redirect domains","Change DNS settings","Create fake DNS servers","Encrypt DNS queries"], "answer":"Corrupt DNS cache to redirect domains"},
                {"question": "Aircrack-ng purpose?", "options":["Wireless network security testing","Web testing","Password cracking","Network scanning"], "answer":"Wireless network security testing"},
                {"question": "What is a honeypot?", "options":["Trap to detect/deflect attacks","Sweet security solution","Password storage","Encryption type"], "answer":"Trap to detect/deflect attacks"},
                {"question": "Symmetric vs asymmetric encryption?", "options":["Symmetric one key, asymmetric public/private","Symmetric faster, asymmetric slower","Symmetric encrypt, asymmetric decrypt","Symmetric DB, asymmetric network"], "answer":"Symmetric one key, asymmetric public/private"},
                {"question": "Privilege escalation?", "options":["Gaining higher access","Increase privileges legally","Create new accounts","Change file permissions"], "answer":"Gaining higher access"},
                {"question": "Purpose of Nikto?", "options":["Find web server vulnerabilities","Scan networks","Crack passwords","Analyze packets"], "answer":"Find web server vulnerabilities"},
                {"question": "Zero-day vulnerability?", "options":["Unknown to vendor, no patch","Existed zero days","Affects systems with zero security","Exploited in zero seconds"], "answer":"Unknown to vendor, no patch"},
                {"question": "ARP spoofing?", "options":["Send falsified ARP messages linking attacker MAC","Encrypt ARP","Block ARP","Accelerate ARP"], "answer":"Send falsified ARP messages linking attacker MAC"},
                {"question": "Purpose of steganography?", "options":["Hide data within other data","Encrypt with multiple algorithms","Secure tunnels","Random passwords"], "answer":"Hide data within other data"},
                {"question": "What is a rootkit?", "options":["Software tools enabling unauthorized access","Root Android devices","Kernel modification tool","Antivirus type"], "answer":"Software tools enabling unauthorized access"},
                {"question": "Vulnerability scanning vs penetration testing?", "options":["Scanning identifies vulnerabilities, testing exploits","Scanning exploits, testing identifies","Scanning automated, testing manual","Scanning networks, testing apps"], "answer":"Scanning identifies vulnerabilities, testing exploits"},
                {"question": "DNSSEC?", "options":["Domain Name System Security Extensions","DNS Security Protocol","Domain Network Security","Digital Network Security Encryption"], "answer":"Domain Name System Security Extensions"},
                {"question": "Purpose of Hydra?", "options":["Password cracking","Network scanning","Vulnerability assessment","Packet analysis"], "answer":"Password cracking"},
                {"question": "Logic bomb?", "options":["Malicious code executes when conditions met","Bomb destroys logic","Encryption type","Hardware vulnerability"], "answer":"Malicious code executes when conditions met"}
            ],
            "Advanced": [
                {"question": "Return-oriented programming (ROP)?", "options":["Uses existing code to bypass DEP","Programming method","Buffer overflow type","Network protocol"], "answer":"Uses existing code to bypass DEP"},
                {"question": "Purpose of Volatility?", "options":["Memory forensics","Network analysis","Password cracking","Vulnerability scanning"], "answer":"Memory forensics"},
                {"question": "Side-channel attack?", "options":["Extract info from physical implementation","Attack secondary channels","DDoS type","Network eavesdropping"], "answer":"Extract info from physical implementation"},
                {"question": "White-box vs Black-box testing?", "options":["White-box internal knowledge, Black-box none","White tests interfaces, Black tests internals","White automated, Black manual","White networks, Black apps"], "answer":"White-box internal knowledge, Black-box none"},
                {"question": "Kerberos authentication?", "options":["Network auth protocol using tickets","Encryption type","Password hashing algorithm","Biometric system"], "answer":"Network auth protocol using tickets"},
                {"question": "Purpose of Sleuth Kit?", "options":["Digital forensics analysis","Network scanning","Password cracking","Vulnerability assessment"], "answer":"Digital forensics analysis"},
                {"question": "Timing attack?", "options":["Exploit time variations to extract info","Attack system clocks","DDoS type","Network latency exploit"], "answer":"Exploit time variations to extract info"},
                {"question": "Purpose of Radare2?", "options":["Reverse engineering","Network analysis","Password cracking","Vulnerability scanning"], "answer":"Reverse engineering"},
                {"question": "DMA attack?", "options":["Direct Memory Access bypass CPU","Database Management Attack","Direct Modification Attack","Data Manipulation Attack"], "answer":"Direct Memory Access bypass CPU"},
                {"question": "Purpose of Bro/Zeek?", "options":["Network security monitoring","Password cracking","Vulnerability assessment","Web testing"], "answer":"Network security monitoring"},
                {"question": "Rowhammer?", "options":["Hardware vulnerability exploiting DRAM","Database attack","Network protocol vulnerability","DDoS type"], "answer":"Hardware vulnerability exploiting DRAM"},
                {"question": "Purpose of Frida?", "options":["Dynamic code instrumentation","Network analysis","Password cracking","Vulnerability scanning"], "answer":"Dynamic code instrumentation"},
                {"question": "Cold boot attack?", "options":["Extract encryption keys from RAM after shutdown","Attack during boot","DDoS type","Hardware vulnerability"], "answer":"Extract encryption keys from RAM after shutdown"},
                {"question": "Purpose of Ghidra?", "options":["Analyze malware","Network scanning","Password cracking","Vulnerability assessment"], "answer":"Analyze malware"},
                {"question": "ROP gadget?", "options":["Small instruction sequences used in exploit","Tool for reverse engineering","Firewall type","Encryption key"], "answer":"Small instruction sequences used in exploit"},
                {"question": "Heap spraying?", "options":["Fill heap with malicious code to exploit buffer","Memory optimization","Packet flooding","Database attack"], "answer":"Fill heap with malicious code to exploit buffer"},
                {"question": "Purpose of YARA?", "options":["Malware identification","Network scanning","Password cracking","Vulnerability assessment"], "answer":"Malware identification"},
                {"question": "Spectre vulnerability?", "options":["CPU speculative execution flaw","Web server vulnerability","Network attack","Buffer overflow"], "answer":"CPU speculative execution flaw"},
                {"question": "Meltdown vulnerability?", "options":["CPU memory isolation flaw","DDoS type","Network attack","Web exploit"], "answer":"CPU memory isolation flaw"},
                {"question": "Purpose of Cuckoo Sandbox?", "options":["Analyze malware in isolated environment","Network scanning","Password cracking","Vulnerability assessment"], "answer":"Analyze malware in isolated environment"},
                {"question": "Purpose of Mimikatz?", "options":["Extract Windows credentials","Network scanning","Password hashing","Vulnerability assessment"], "answer":"Extract Windows credentials"},
                {"question": "Format string vulnerability?", "options":["Exploit printf style functions","Network attack","Password attack","Buffer overflow"], "answer":"Exploit printf style functions"},
                {"question": "Purpose of OpenVAS?", "options":["Vulnerability scanning","Network scanning","Password cracking","Web testing"], "answer":"Vulnerability scanning"},
                {"question": "Spectre variant 1 vs 2?", "options":["Different speculative execution methods","Different CPUs","Different malware","Different OS versions"], "answer":"Different speculative execution methods"},
                {"question": "Rowhammer double-sided?", "options":["Hammering two rows simultaneously to flip bits","Single row hammering","Memory leak","CPU attack"], "answer":"Hammering two rows simultaneously to flip bits"},
                {"question": "ROP chain?", "options":["Sequence of gadgets to perform attack","Malware chain","Password chain","Network chain"], "answer":"Sequence of gadgets to perform attack"},
                {"question": "Purpose of Metasploit auxiliary modules?", "options":["Scanning and info gathering","Exploiting vulnerabilities","Password cracking","Memory analysis"], "answer":"Scanning and info gathering"},
                {"question": "Heap overflow vs stack overflow?", "options":["Overflow heap memory vs stack memory","Same thing","Different OS","Different network protocols"], "answer":"Overflow heap memory vs stack memory"},
                {"question": "DLL injection?", "options":["Inject DLL into process memory","Inject malware into network","Inject code in DB","Inject password"], "answer":"Inject DLL into process memory"},
                {"question": "ROP bypass DEP?", "options":["Use gadgets to execute code despite DEP","Use network tools","Exploit passwords","Bypass firewall"], "answer":"Use gadgets to execute code despite DEP"},
                {"question": "ASLR bypass?", "options":["Predict memory locations to exploit","Encrypt memory","Change file permissions","Attack network"], "answer":"Predict memory locations to exploit"}
            ]
        }

    def setup_ui(self):
        title = tk.Label(self.window, text="DFNC1 - Kali Linux Cyber Security Quiz", font=("Arial",24,"bold"), fg="#4ecca3", bg="#1a1a2e")
        title.pack(pady=20)

        instructions = tk.Label(self.window, text="90 cybersecurity questions. 10 seconds per question.", font=("Arial",12), fg="#eeeeee", bg="#1a1a2e")
        instructions.pack(pady=10)

        self.q_frame = tk.Frame(self.window, bg="#16213e", relief=tk.RAISED, bd=3)
        self.q_frame.pack(pady=20, padx=40, fill=tk.BOTH, expand=True)

        self.progress_label = tk.Label(self.window, text="", font=("Arial",12), fg="#eeeeee", bg="#1a1a2e")
        self.progress_label.pack(pady=10)

        self.timer_label = tk.Label(self.window, text="Time left: 10s", font=("Arial",14,"bold"), fg="#f8b400", bg="#1a1a2e")
        self.timer_label.pack(pady=10)

        self.start_btn = tk.Button(self.window, text="Start Quiz", command=self.start_quiz, font=("Arial",16), bg="#4ecca3", fg="#000", relief=tk.RAISED, bd=3, width=15)
        self.start_btn.pack(pady=20)

        self.score_label = tk.Label(self.window, text="", font=("Arial",16), fg="#4ecca3", bg="#1a1a2e")
        self.score_label.pack(pady=10)

        tool_label = tk.Label(self.window, text="DFNC1 Tool v1.0", font=("Arial",10), fg="#888888", bg="#1a1a2e")
        tool_label.pack(side=tk.BOTTOM, pady=5)

    def start_quiz(self):
        self.start_btn.pack_forget()
        self.current_level = 0
        self.current_question = 0
        self.score = 0
        self.quiz_active = True
        self.show_question()

    def show_question(self):
        for widget in self.q_frame.winfo_children():
            widget.destroy()

        level_label = tk.Label(self.q_frame, text=f"Level: {self.levels[self.current_level]}", font=("Arial",16,"bold"), fg="#f8b400", bg="#16213e")
        level_label.pack(pady=10)

        level_questions = self.questions[self.levels[self.current_level]]
        q_data = level_questions[self.current_question]

        question_text = tk.Label(self.q_frame, text=q_data["question"], font=("Arial",14), wraplength=700, justify=tk.LEFT, fg="#eeeeee", bg="#16213e")
        question_text.pack(pady=20)

        self.answer_var = tk.StringVar()
        for option in q_data["options"]:
            rb = tk.Radiobutton(self.q_frame, text=option, variable=self.answer_var, value=option, font=("Arial",12), bg="#16213e", fg="#eeeeee", selectcolor="#1a1a2e", activebackground="#16213e")
            rb.pack(anchor=tk.W, padx=50, pady=5)

        next_btn = tk.Button(self.q_frame, text="Next", command=self.check_answer, font=("Arial",14), bg="#4ecca3", fg="#000", relief=tk.RAISED, bd=2)
        next_btn.pack(pady=20)

        total_q = sum(len(self.questions[level]) for level in self.levels)
        current_q = self.current_question + 1 + sum(len(self.questions[l]) for l in self.levels[:self.current_level])
        self.progress_label.config(text=f"Question {current_q} of {total_q}")

        self.time_left = 10
        self.update_timer()

    def update_timer(self):
        if self.time_left > 0 and self.quiz_active:
            self.timer_label.config(text=f"Time left: {self.time_left}s")
            self.time_left -= 1
            self.timer = self.window.after(1000, self.update_timer)
        elif self.quiz_active:
            self.timer_label.config(text="Time's up!", fg="#ff0000")
            messagebox.showinfo("Time's up","Time has run out! Moving to next question.")
            self.check_answer()

    def check_answer(self):
        if self.timer:
            self.window.after_cancel(self.timer)
            self.timer = None

        level_questions = self.questions[self.levels[self.current_level]]
        q_data = level_questions[self.current_question]

        if self.answer_var.get() == q_data["answer"]:
            self.score += 1

        self.current_question += 1

        if self.current_question >= len(level_questions):
            self.current_question = 0
            self.current_level += 1
            if self.current_level >= len(self.levels):
                self.quiz_active = False
                self.show_results()
                return

        self.show_question()

    def show_results(self):
        for widget in self.q_frame.winfo_children():
            widget.destroy()

        total_q = sum(len(self.questions[level]) for level in self.levels)
        percentage = (self.score/total_q)*100
        result_text = f"Quiz Completed!\nScore: {self.score}/{total_q}\nPercentage: {percentage:.2f}%"
        result_label = tk.Label(self.q_frame, text=result_text, font=("Arial",18,"bold"), fg="#4ecca3", bg="#16213e")
        result_label.pack(pady=50)

        if percentage >= 80:
            message = "Excellent! Advanced knowledge!"
        elif percentage >= 60:
            message = "Good job! Solid knowledge!"
        else:
            message = "Keep learning! Cybersecurity is continuous."
        msg_label = tk.Label(self.q_frame, text=message, font=("Arial",14), fg="#f8b400", bg="#16213e")
        msg_label.pack(pady=10)

        self.start_btn.config(text="Restart Quiz")
        self.start_btn.pack(pady=20)
        self.timer_label.config(text="")
        self.progress_label.config(text="")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = DFNC1Quiz()
    app.run()
