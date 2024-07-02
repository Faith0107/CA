import socket
import json
import tkinter as tk
from tkinter import filedialog

Server_IP = '192.168.183.139'

def send_request(action, cert=None):
    request = {"action": action}
    
    if action == 'apply':
        request.update({
            "country": entry_country.get(),
            "state": entry_state.get(),
            "city": entry_city.get(),
            "organization": entry_organization.get(),
            "common_name": entry_common_name.get()
        })
    elif action == 'validate' and cert:
        request["cert"] = cert
    elif action == 'revoke' and cert:
        request["cert"] = cert
        request["common_name"] = entry_common_name.get()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((Server_IP, 12345))
            s.sendall(json.dumps(request).encode('utf-8'))
            response = s.recv(4096).decode('utf-8')
            
            if action == 'apply':
                save_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(response.encode('utf-8'))
                    label_response.config(text="证书已保存")
            elif action == 'validate':
                response_data = json.loads(response)
                if response_data['status'] == 'valid':
                    label_response.config(text="证书有效")
                elif response_data['status'] == 'revoked':
                    label_response.config(text="证书已吊销")
                else:
                    label_response.config(text=f"证书无效: {response_data['error']}")
            elif action == 'revoke':
                response_data = json.loads(response)
                if response_data['status'] == 'revoked':
                    label_response.config(text="证书已吊销")
                elif response_data['status'] == 'already_revoked':
                    label_response.config(text="证书已被吊销")
                elif response_data['status'] == 'unauthorized':
                    label_response.config(text="未授权的吊销请求")

    except Exception as e:
        label_response.config(text=f"连接失败：{e}")

def validate_certificate():
    cert_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if cert_path:
        with open(cert_path, 'r') as f:
            cert_pem = f.read()
        send_request('validate', cert=cert_pem)

def revoke_certificate():
    cert_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if cert_path:
        with open(cert_path, 'r') as f:
            cert_pem = f.read()
        send_request('revoke', cert=cert_pem)

root = tk.Tk()
root.title("数字证书管理")

frame_buttons = tk.Frame(root)
frame_buttons.pack(side="top", fill="x")

frame_apply = tk.Frame(root)
frame_validate = tk.Frame(root)
frame_revoke = tk.Frame(root)

def show_frame(frame):
    frame_apply.pack_forget()
    frame_validate.pack_forget()
    frame_revoke.pack_forget()
    frame.pack(fill="both", expand=True)

tk.Button(frame_buttons, text="申请证书", command=lambda: show_frame(frame_apply)).pack(side="left")
tk.Button(frame_buttons, text="验证证书", command=lambda: show_frame(frame_validate)).pack(side="left")
tk.Button(frame_buttons, text="吊销证书", command=lambda: show_frame(frame_revoke)).pack(side="left")

frame_apply.pack(fill="both", expand=True)

# 申请证书部分
tk.Label(frame_apply, text="国家").grid(row=0, column=0)
entry_country = tk.Entry(frame_apply)
entry_country.grid(row=0, column=1)
tk.Label(frame_apply, text="省份").grid(row=1, column=0)
entry_state = tk.Entry(frame_apply)
entry_state.grid(row=1, column=1)
tk.Label(frame_apply, text="城市").grid(row=2, column=0)
entry_city = tk.Entry(frame_apply)
entry_city.grid(row=2, column=1)
tk.Label(frame_apply, text="单位").grid(row=3, column=0)
entry_organization = tk.Entry(frame_apply)
entry_organization.grid(row=3, column=1)
tk.Label(frame_apply, text="申请人").grid(row=4, column=0)
entry_common_name = tk.Entry(frame_apply)
entry_common_name.grid(row=4, column=1)
tk.Button(frame_apply, text="提交申请", command=lambda: send_request('apply')).grid(row=5, column=1)

# 验证证书部分
tk.Button(frame_validate, text="选择证书并验证", command=validate_certificate).pack()

# 吊销证书部分
tk.Button(frame_revoke, text="选择证书并吊销", command=revoke_certificate).pack()

label_response = tk.Label(root)
label_response.pack(side="bottom", fill="x")

root.mainloop()
