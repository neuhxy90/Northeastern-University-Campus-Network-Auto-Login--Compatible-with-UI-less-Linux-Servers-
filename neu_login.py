"""
东北大学校园网自动登录 - Python版本
支持深澜(srun)认证
"""

import re
import json
import time
import hashlib
import hmac
import os
import base64
import requests
from urllib.parse import urlencode, quote, urlparse


class NEULogin:
    """东北大学校园网登录类"""

    # 基础配置
    BASE_URL = "https://pass.neu.edu.cn"
    LOGIN_POINT = f"{BASE_URL}/tpass/login"
    # 深澜认证相关URL
    SRUN_PORTAL = "http://ipgw.neu.edu.cn"
    SRUN_API = f"{SRUN_PORTAL}/cgi-bin/srun_portal"
    SRUN_GET_CHALLENGE = f"{SRUN_PORTAL}/cgi-bin/get_challenge"
    SRUN_RAD_USER_INFO = f"{SRUN_PORTAL}/cgi-bin/rad_user_info"
    # SSO认证URL (注意是v1路径)
    SRUN_SSO_URL = f"{SRUN_PORTAL}/v1/srun_portal_sso"
    AC_ID = "16"  # 校园网ac_id
    N = "200"
    TYPE = "1"
    ENC = "srun_bx1"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(self._default_headers())
        self.session.verify = False  # 允许不安全请求
        self.session.timeout = 30
        self.token = ""
        self.ip = ""
        # 动态获取RSA公钥
        self.RSA_PUBLIC_KEY = self._fetch_rsa_public_key()

    def _fetch_rsa_public_key(self) -> str:
        """动态获取RSA公钥"""
        try:
            from datetime import datetime
            current_date = datetime.now().strftime("%Y%m%d")
            js_url = f"https://pass.neu.edu.cn/tpass/comm/neu/js/login_neu.js?v={current_date}"
            
            response = self.session.get(js_url)
            response.raise_for_status()
            
            # 从JS文件中提取publicKeyStr变量
            import re
            pattern = r'publicKeyStr\s*=\s*["\']([^"\']+)["\']'
            match = re.search(pattern, response.text)
            
            if match:
                public_key = match.group(1)
                print(f"✅ 成功获取RSA公钥，长度: {len(public_key)}")
                return public_key
            else:
                print("⚠️ 未找到publicKeyStr变量，使用默认公钥")
                return self._get_default_rsa_public_key()
        except Exception as e:
            print(f"⚠️ 获取RSA公钥失败: {e}，使用默认公钥")
            return self._get_default_rsa_public_key()

    def _get_default_rsa_public_key(self) -> str:
        """返回默认的RSA公钥"""
        return "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnjA28DLKXZzxbKmo9/1WkVLf1mr+wtLXLXt6sC4WiBCtsbzF5ewm7ARZeAdS3iZtqlYPn6IcUoOw42H8nAK/tfFcIb6dZ1K0atn0U39oWCGPzYuKtLJeMuNZiDXVuAXtojrckOjLW9B3gUnaNGLuIx0fYe66l0o9WjU2cGLNZQfiIxs2h00z1EA9IdSnVxiVQWSD+lsP3JZXh2TT287la4Y4603SQNKTK/QvXfcmccwTEd1IW6HwGxD6QrkInBiHisKWxmveN7UDSaQRZ/J97G0YC32pD38WT53izXeK0p/kU/X37VP555um1wVWFvPIuc9I7gMP1+hq5a+X6c++tQIDAQAB"
    
    @staticmethod
    def _default_headers():
        """默认请求头"""
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
    
    @staticmethod
    def _parse_der_public_key(der_bytes: bytes) -> tuple:
        """解析DER编码的SubjectPublicKeyInfo，提取RSA公钥(n, e)"""
        def read_tag_length(data, pos):
            tag = data[pos]; pos += 1
            length = data[pos]; pos += 1
            if length & 0x80:
                num_bytes = length & 0x7f
                length = int.from_bytes(data[pos:pos + num_bytes], 'big')
                pos += num_bytes
            return tag, length, pos

        def read_integer(data, pos):
            tag, length, pos = read_tag_length(data, pos)
            assert tag == 0x02, f"Expected INTEGER (0x02), got {hex(tag)}"
            value = int.from_bytes(data[pos:pos + length], 'big')
            return value, pos + length

        pos = 0
        # 外层 SEQUENCE (SubjectPublicKeyInfo)
        tag, length, pos = read_tag_length(der_bytes, pos)
        assert tag == 0x30
        # AlgorithmIdentifier SEQUENCE — 跳过
        tag, length, pos = read_tag_length(der_bytes, pos)
        assert tag == 0x30
        pos += length
        # BIT STRING
        tag, length, pos = read_tag_length(der_bytes, pos)
        assert tag == 0x03
        pos += 1  # 跳过 unused-bits 字节
        # 内层 SEQUENCE (RSAPublicKey)
        tag, length, pos = read_tag_length(der_bytes, pos)
        assert tag == 0x30
        # 读取 n 和 e
        n, pos = read_integer(der_bytes, pos)
        e, pos = read_integer(der_bytes, pos)
        return n, e

    def _rsa_encrypt(self, plaintext: str) -> str:
        """使用RSA公钥加密（PKCS1v15填充）—— 纯Python实现，无需第三方库"""
        der_bytes = base64.b64decode(self.RSA_PUBLIC_KEY)
        n, e = self._parse_der_public_key(der_bytes)
        key_size = (n.bit_length() + 7) // 8  # 密钥字节长度

        msg_bytes = plaintext.encode('utf-8')
        if len(msg_bytes) > key_size - 11:
            raise ValueError("消息过长，超出此RSA密钥可加密的上限")

        # PKCS#1 v1.5 填充: 0x00 0x02 [随机非零字节] 0x00 [明文]
        pad_len = key_size - len(msg_bytes) - 3
        padding = b''
        while len(padding) < pad_len:
            chunk = os.urandom(pad_len - len(padding))
            padding += bytes(b for b in chunk if b != 0)
        padding = padding[:pad_len]

        padded = b'\x00\x02' + padding + b'\x00' + msg_bytes

        # RSA 核心运算: ciphertext = plaintext^e mod n
        m_int = int.from_bytes(padded, 'big')
        c_int = pow(m_int, e, n)
        encrypted = c_int.to_bytes(key_size, 'big')

        return base64.b64encode(encrypted).decode('utf-8')
    
    def _parse_field(self, html: str, name: str) -> str | None:
        """解析HTML中的隐藏字段值"""
        patterns = [
            rf'name="{name}"\s+value="([^"]+)"',
            rf"name='{name}'\s+value='([^']+)'"
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        return None
    
    def _extract_lt_execution(self, html: str) -> tuple[str, str]:
        """解析lt和execution参数"""
        lt = self._parse_field(html, "lt")
        execution = self._parse_field(html, "execution")
        
        if not lt or not execution:
            raise Exception(f"无法获取登录参数 - lt:{bool(lt)}, execution:{bool(execution)}")
        
        return lt, execution
    
    def _extract_ticket_from_url(self, url: str) -> str | None:
        """从URL中提取ticket"""
        match = re.search(r'ticket=([^&]+)', url)
        return match.group(1) if match else None
    
    def _ensure_not_error_page(self, html: str):
        """检查是否为错误页面"""
        if "404" in html or "403" in html:
            raise Exception("服务器返回错误页面")
    
    # =============== 深澜认证加密算法 ===============
    
    def _get_xencode(self, msg, key):
        """XEncode加密"""
        if msg == "":
            return ""
        
        pwd = []
        for i in range(len(msg)):
            pwd.append(ord(msg[i]))
        
        if len(key) < 4:
            key = key + [0] * (4 - len(key))
        
        n = len(pwd) - 1
        z = pwd[n]
        c = 0x86014019 | 0x183639A0
        q = 6 + 52 // (n + 1)
        d = 0
        
        while q > 0:
            d = (d + 0x9E3779B9) & 0xFFFFFFFF
            e = (d >> 2) & 3
            for p in range(n):
                y = pwd[p + 1]
                m = (z >> 5) ^ (y << 2)
                m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
                m += key[(p & 3) ^ e] ^ z
                pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
                z = pwd[p]
            
            y = pwd[0]
            m = (z >> 5) ^ (y << 2)
            m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
            m += key[(n & 3) ^ e] ^ z
            pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
            z = pwd[n]
            q -= 1
        
        return self._encode(pwd, False)
    
    def _encode(self, msg, flag):
        """编码"""
        if flag:
            s = []
            for i in msg:
                s.append(ord(i))
            return s
        
        l = len(msg)
        ll = (l - 1) << 2
        
        if msg[l - 1] == 0:
            return ""
        
        m = (msg[l - 1])
        if m < ll - 3 or m > ll:
            return ""
        ll = m
        
        s = ""
        for i in range(l):
            s += chr(msg[i] & 0xff)
            s += chr((msg[i] >> 8) & 0xff)
            s += chr((msg[i] >> 16) & 0xff)
            s += chr((msg[i] >> 24) & 0xff)
        
        return s[:ll]
    
    def _s(self, msg, flag):
        """编码转换"""
        if flag:
            s = []
            for i in range(0, len(msg), 4):
                val = 0
                for j in range(4):
                    if i + j < len(msg):
                        val |= ord(msg[i + j]) << (8 * j)
                s.append(val)
            return s
        else:
            s = ""
            for w in msg:
                s += chr(w & 0xff)
                s += chr((w >> 8) & 0xff)
                s += chr((w >> 16) & 0xff)
                s += chr((w >> 24) & 0xff)
            return s
    
    def _get_base64(self, msg):
        """Base64编码"""
        import base64
        return base64.b64encode(msg.encode('latin-1')).decode()
    
    def _get_md5(self, password, token):
        """MD5加密"""
        return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()
    
    def _get_sha1(self, value):
        """SHA1加密"""
        return hashlib.sha1(value.encode()).hexdigest()
    
    def _get_info(self, username, password, ip):
        """生成info参数"""
        info = {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": self.AC_ID,
            "enc_ver": self.ENC
        }
        return "{SRBX1}" + self._get_base64(self._get_xencode(json.dumps(info, separators=(',', ':')), self._s(self.token, True)))
    
    def _get_chksum(self, username, hmd5, ip, info):
        """生成校验和"""
        chkstr = self.token + username
        chkstr += self.token + hmd5
        chkstr += self.token + self.AC_ID
        chkstr += self.token + ip
        chkstr += self.token + self.N
        chkstr += self.token + self.TYPE
        chkstr += self.token + info
        return self._get_sha1(chkstr)
    
    def login(self, username: str, password: str) -> dict:
        """
        执行登录操作 - CAS统一身份认证 -> IPGW SSO
        
        Args:
            username: 用户名（学号）
            password: 密码
            
        Returns:
            包含登录结果的字典
        """
        try:
            if not username or not password:
                raise Exception("用户名或密码不能为空")
            
            # 每次登录使用全新的session，避免旧cookie干扰
            self.session = requests.Session()
            self.session.headers.update(self._default_headers())
            self.session.verify = False
            self.session.timeout = 30
            
            print("开始登录流程...")
            
            # ========== 第一步：构建CAS登录URL ==========
            print("\n===== 步骤1: CAS统一身份认证 =====")
            
            cas_service_url = "http://ipgw.neu.edu.cn/srun_portal_sso?ac_id=1"
            cas_login_url = f"{self.LOGIN_POINT}?service={quote(cas_service_url, safe='')}"
            
            print(f"CAS登录URL: {cas_login_url}")
            
            # 获取CAS登录页面
            cas_resp = self.session.get(cas_login_url, allow_redirects=True)
            print(f"CAS页面状态: {cas_resp.status_code}")
            print(f"CAS最终URL: {cas_resp.url}")
            
            # 判断是否被重定向到了校园网（只检查hostname，不检查查询参数）
            final_host = urlparse(cas_resp.url).hostname
            
            if final_host and 'ipgw.neu.edu.cn' in final_host:
                print("✅ CAS会话有效，已重定向到校园网")
                
                # 已经到达校园网页面，检查是否登录成功
                if '网络已连接' in cas_resp.text:
                    print("✅ 登录成功！")
                    return {"success": True, "message": "校园网登录成功", "data": {}}
                
                # 页面可能还需要完成SSO认证
                if 'ticket=' in cas_resp.url:
                    ticket = self._extract_ticket_from_url(cas_resp.url)
                    print(f"获取到ticket: {ticket}")
                    return self._complete_sso(ticket)
                    
                print("⚠️ 重定向到校园网但未完成认证")
            
            # ========== 第二步：提交CAS登录表单 ==========
            print("\n===== 步骤2: 提交CAS登录 =====")
            
            cas_page = cas_resp.text
            self._ensure_not_error_page(cas_page)
            
            lt, execution = self._extract_lt_execution(cas_page)
            print(f"✅ lt: {lt[:40]}...")
            print(f"✅ execution: {execution}")
            
            # CAS系统已升级为RSA加密: rsa = RSA_encrypt(username + password)
            rsa_encrypted = self._rsa_encrypt(username + password)
            print(f"✅ RSA加密完成，密文长度: {len(rsa_encrypted)}")
            
            payload = {
                "rsa": rsa_encrypted,
                "ul": str(len(username)),
                "pl": str(len(password)),
                "lt": lt,
                "execution": execution,
                "_eventId": "submit"
            }
            
            headers = {
                **self._default_headers(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": cas_login_url,
                "Origin": self.BASE_URL
            }
            
            login_resp = self.session.post(cas_login_url, data=payload, headers=headers, allow_redirects=True)
            # 跳过邮箱登陆页面 二次访问即可
            login_resp = self.session.get(cas_login_url, headers=headers, allow_redirects=True)
            print(f"登录响应状态: {login_resp.status_code}")
            print(f"登录后URL: {login_resp.url}")
            
            # 处理HTTP 500等服务器错误 - 重试一次
            if login_resp.status_code >= 500:
                print("⚠️ CAS服务器错误，清除cookie后重试...")
                self.session.cookies.clear()
                cas_resp2 = self.session.get(cas_login_url, allow_redirects=True)
                
                final_host2 = urlparse(cas_resp2.url).hostname
                if final_host2 and 'ipgw.neu.edu.cn' in final_host2:
                    if 'ticket=' in cas_resp2.url:
                        ticket = self._extract_ticket_from_url(cas_resp2.url)
                        return self._complete_sso(ticket)
                    if '网络已连接' in cas_resp2.text:
                        return {"success": True, "message": "校园网登录成功", "data": {}}
                
                # 仍然在CAS页面，重新登录
                lt2, execution2 = self._extract_lt_execution(cas_resp2.text)
                payload["rsa"] = self._rsa_encrypt(username + password)
                payload["lt"] = lt2
                payload["execution"] = execution2
                login_resp = self.session.post(cas_login_url, data=payload, headers=headers, allow_redirects=True)
                print(f"重试登录响应状态: {login_resp.status_code}")
                print(f"重试登录后URL: {login_resp.url}")
            
            # ========== 第三步：检查登录结果 ==========
            print("\n===== 步骤3: 检查登录结果 =====")
            
            login_final_host = urlparse(login_resp.url).hostname
            
            # 登录成功 - 已跳转到校园网
            if login_final_host and 'ipgw.neu.edu.cn' in login_final_host:
                if '网络已连接' in login_resp.text:
                    print("✅ 登录成功！")
                    return {"success": True, "message": "校园网登录成功", "data": {}}
                
                if 'ticket=' in login_resp.url:
                    ticket = self._extract_ticket_from_url(login_resp.url)
                    print(f"获取到ticket: {ticket}")
                    return self._complete_sso(ticket)
            
            # 检查是否账号密码错误
            if '密码' in login_resp.text or '认证失败' in login_resp.text or '错误' in login_resp.text:
                raise Exception("用户名或密码错误")
            
            # ========== 第四步：最后检查在线状态 ==========
            print("\n===== 步骤4: 检查在线状态 =====")
            
            import time as t
            t.sleep(1)
            
            status = self.get_status()
            if status.get("online"):
                print("✅ 确认登录成功！")
                return {"success": True, "message": "校园网登录成功", "data": status.get("data", {})}
            
            raise Exception("登录流程完成但未检测到在线状态，请检查账号密码或网络")
            
        except Exception as e:
            print(f"❌ 登录失败: {str(e)}")
            return {"success": False, "message": f"登录失败: {str(e)}"}
    
    def _complete_sso(self, ticket: str) -> dict:
        """使用ticket完成IPGW SSO认证"""
        import time as t
        
        print(f"\n===== 完成SSO认证 (ticket: {ticket[:20]}...) =====")
        sso_url = f"{self.SRUN_SSO_URL}?ac_id=1&ticket={ticket}"
        sso_resp = self.session.get(sso_url, allow_redirects=True)
        print(f"SSO响应状态: {sso_resp.status_code}")
        
        if '网络已连接' in sso_resp.text:
            print("✅ SSO认证成功！")
            return {"success": True, "message": "校园网登录成功", "data": {}}
        
        # 等待后检查状态
        t.sleep(1)
        status = self.get_status()
        if status.get("online"):
            print("✅ SSO认证成功！")
            return {"success": True, "message": "校园网登录成功", "data": status.get("data", {})}
        
        raise Exception("SSO认证完成但未检测到在线状态")
    
    def logout(self) -> dict:
        """
        执行下线操作 - 使用深澜认证
        
        Returns:
            包含下线结果的字典
        """
        try:
            print("开始下线流程...")
            
            # 先获取当前用户信息
            rad_resp = self.session.get(self.SRUN_RAD_USER_INFO, params={"callback": "jsonp"})
            json_match = re.search(r'\((\{.*\})\)', rad_resp.text)
            
            username = ""
            ip = ""
            
            if json_match:
                try:
                    user_info = json.loads(json_match.group(1))
                    username = user_info.get("user_name", "")
                    ip = user_info.get("online_ip", "")
                    print(f"当前用户: {username}, IP: {ip}")
                except:
                    pass
            
            if not ip:
                # 尝试获取IP
                init_resp = self.session.get(self.SRUN_PORTAL)
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', init_resp.text)
                if ip_match:
                    ip = ip_match.group(1)
            
            # 发送下线请求
            callback = f"jsonp_{int(time.time() * 1000)}"
            logout_params = {
                "callback": callback,
                "action": "logout",
                "username": username,
                "ip": ip,
                "ac_id": self.AC_ID,
                "_": int(time.time() * 1000)
            }
            
            logout_resp = self.session.get(self.SRUN_API, params=logout_params)
            logout_text = logout_resp.text
            
            print(f"下线响应: {logout_text}")
            
            # 解析响应
            json_match = re.search(r'\((\{.*\})\)', logout_text)
            if json_match:
                result = json.loads(json_match.group(1))
                if result.get("error") == "ok":
                    return {"success": True, "message": "校园网下线成功", "data": result}
                else:
                    error_msg = result.get("error_msg", result.get("error", "未知错误"))
                    return {"success": False, "message": f"下线失败: {error_msg}"}
            
            return {"success": True, "message": "下线请求已发送", "data": {"response": logout_text}}
                
        except Exception as e:
            print(f"❌ 下线失败: {str(e)}")
            return {"success": False, "message": f"下线失败: {str(e)}"}
    
    def get_status(self) -> dict:
        """
        获取当前网络状态
        
        Returns:
            包含网络状态的字典
        """
        try:
            # 检查深澜认证状态
            rad_resp = self.session.get(self.SRUN_RAD_USER_INFO, params={"callback": "jsonp"}, timeout=5)
            print(f"状态检查响应: {rad_resp.text[:500]}")
            
            json_match = re.search(r'\((\{.*\})\)', rad_resp.text)
            
            if json_match:
                try:
                    user_info = json.loads(json_match.group(1))
                    print(f"用户信息: {user_info}")
                    username = user_info.get("user_name", "")
                    online_ip = user_info.get("online_ip", "")
                    
                    if username and online_ip:
                        return {
                            "success": True, 
                            "online": True, 
                            "message": f"已登录 - 用户: {username}, IP: {online_ip}",
                            "data": user_info
                        }
                except Exception as e:
                    print(f"解析用户信息失败: {e}")
            
            return {"success": True, "online": False, "message": "未登录校园网"}
                
        except Exception as e:
            return {"success": True, "online": False, "message": f"网络状态未知: {str(e)}"}


# 禁用不安全请求警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if __name__ == "__main__":
    # 测试登录
    login = NEULogin()
    
    # 测试用例
    username = input("请输入学号: ")
    password = input("请输入密码: ")
    
    result = login.login(username, password)
    print(result)
