"""
Xiaomi设备AuthKey获取工具 - Flask应用
部署到Vercel: https://vercel.com/
"""

import base64
import hashlib
import hmac
import json
import random
import string
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

import requests
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

# 用于存储会话状态的简单内存存储（在生产环境中应使用Redis或数据库）
sessions = {}

@dataclass
class MiAccountToken:
    """小米账户令牌"""
    ssecurity: str
    service_token: str
    c_user_id: str
    
@dataclass
class DeviceAuthKey:
    """设备认证密钥信息"""
    device_id: str
    device_name: str
    model: str
    token: str
    beacon_key: str
    mac_address: str

class XiaomiAuth:
    """小米认证和API客户端"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept': 'application/json, text/plain, */*'
        })
    
    def generate_nonce(self) -> str:
        """生成nonce值"""
        millis = int(time.time() * 1000)
        rand_part = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        nonce_data = rand_part.encode() + (millis // 60000).to_bytes(4, 'big')
        return base64.b64encode(nonce_data).decode()
    
    def calculate_signature(self, path: str, signed_nonce: str, params: Dict[str, str]) -> str:
        """计算签名"""
        # 按ASCII顺序排序参数
        sorted_params = sorted(params.items())
        param_str = '&'.join([f'{k}={v}' for k, v in sorted_params])
        
        # 构建签名字符串
        sign_str = f'POST&{path}&{param_str}&{signed_nonce}'
        
        # 计算SHA1哈希
        sha1_hash = hashlib.sha1(sign_str.encode()).digest()
        return base64.b64encode(sha1_hash).decode()
    
    def rc4_encrypt(self, key: bytes, data: str) -> str:
        """RC4加密"""
        # 简单的RC4实现
        S = list(range(256))
        j = 0
        key_bytes = key
        
        # KSA
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA
        i = j = 0
        result = []
        
        for char in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(chr(ord(char) ^ k))
        
        return ''.join(result)
    
    def login(self, username: str, password: str) -> Optional[MiAccountToken]:
        """登录小米账户"""
        try:
            # 步骤1: 获取_sign
            login_url = "https://account.xiaomi.com/pass/serviceLogin"
            params = {
                'sid': 'miio',
                '_json': 'true'
            }
            
            response = self.session.get(login_url, params=params)
            if response.status_code != 200:
                return None
            
            # 解析_sign
            content = response.text
            if '&&&START&&&' in content:
                content = content.split('&&&START&&&')[1]
            
            try:
                data = json.loads(content)
                _sign = data.get('_sign', '')
            except:
                _sign = ''
            
            # 步骤2: 服务登录认证
            auth_url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
            
            # 计算密码哈希
            md5_hash = hashlib.md5(password.encode()).hexdigest().upper()
            
            auth_data = {
                'sid': 'miio',
                'hash': md5_hash,
                'callback': 'https://sts.io.mi.com/sts',
                'qs': '%3Fsid%3Dmiio%26_json%3Dtrue',
                'user': username,
                '_sign': _sign,
                '_json': 'true'
            }
            
            response = self.session.post(auth_url, data=auth_data)
            if response.status_code != 200:
                return None
            
            # 解析认证响应
            content = response.text
            if '&&&START&&&' in content:
                content = content.split('&&&START&&&')[1]
            
            auth_result = json.loads(content)
            
            if auth_result.get('code') != 0:
                return None
            
            ssecurity = auth_result.get('ssecurity', '')
            location = auth_result.get('location', '')
            c_user_id = auth_result.get('cUserId', '')
            
            if not ssecurity or not location:
                return None
            
            # 步骤3: 获取serviceToken
            response = self.session.get(location, allow_redirects=True)
            
            # 从cookies中获取serviceToken
            cookies = self.session.cookies.get_dict()
            service_token = cookies.get('serviceToken', '')
            
            if not service_token:
                # 尝试从响应中提取
                if 'serviceToken=' in response.text:
                    token_start = response.text.find('serviceToken=') + 13
                    token_end = response.text.find(';', token_start)
                    service_token = response.text[token_start:token_end]
            
            return MiAccountToken(
                ssecurity=ssecurity,
                service_token=service_token,
                c_user_id=c_user_id
            )
            
        except Exception as e:
            print(f"登录错误: {e}")
            return None
    
    def get_device_list(self, token: MiAccountToken) -> List[Dict]:
        """获取设备列表"""
        try:
            # 准备参数
            nonce = self.generate_nonce()
            
            # 计算signed_nonce
            ssecurity_bytes = base64.b64decode(token.ssecurity)
            nonce_bytes = base64.b64decode(nonce)
            signed_nonce = hashlib.sha256(ssecurity_bytes + nonce_bytes).digest()
            signed_nonce_b64 = base64.b64encode(signed_nonce).decode()
            
            # 构建请求参数
            params = {
                'data': '{"getVirtualModel":false,"getHuamiDevices":0}'
            }
            
            # 计算签名
            path = '/home/device_list'
            signature = self.calculate_signature(path, signed_nonce_b64, params)
            
            # 加密参数
            key = signed_nonce
            encrypted_data = self.rc4_encrypt(key.encode(), json.dumps(params))
            
            # 构建最终请求数据
            request_data = {
                'signature': signature,
                '_nonce': nonce,
                'data': encrypted_data
            }
            
            # 设置请求头
            headers = {
                'User-Agent': 'MiHome/6.0.103 (com.xiaomi.mihome; iOS 14.4)',
                'Accept-Language': 'zh-cn',
                'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2'
            }
            
            # 设置cookies
            cookies = {
                'userId': token.c_user_id,
                'serviceToken': token.service_token,
                'locale': 'zh_CN'
            }
            
            # 发送请求
            api_url = "https://api.io.mi.com/app/home/device_list"
            response = requests.post(
                api_url,
                data=request_data,
                headers=headers,
                cookies=cookies
            )
            
            if response.status_code == 200:
                # 解密响应
                encrypted_response = response.text.strip('"')
                decrypted_response = self.rc4_encrypt(key.encode(), encrypted_response)
                
                try:
                    result = json.loads(decrypted_response)
                    if result.get('code') == 0:
                        return result.get('result', {}).get('list', [])
                except:
                    pass
            
            return []
            
        except Exception as e:
            print(f"获取设备列表错误: {e}")
            return []
    
    def extract_auth_keys(self, device_list: List[Dict]) -> List[DeviceAuthKey]:
        """从设备列表中提取认证密钥"""
        auth_keys = []
        
        for device in device_list:
            try:
                detail = device.get('detail', {})
                
                auth_key = DeviceAuthKey(
                    device_id=device.get('did', ''),
                    device_name=device.get('name', '未知设备'),
                    model=device.get('model', '未知型号'),
                    token=detail.get('token', ''),
                    beacon_key=detail.get('beaconkey', ''),
                    mac_address=detail.get('mac', '')
                )
                
                auth_keys.append(auth_key)
            except:
                continue
        
        return auth_keys

# HTML模板
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>小米设备AuthKey获取工具</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            color: white;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
        }
        
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s;
        }
        
        button:hover {
            transform: translateY(-2px);
        }
        
        button:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #667eea;
        }
        
        .result-card {
            display: none;
        }
        
        .device-list {
            margin-top: 20px;
        }
        
        .device-item {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }
        
        .device-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .device-name {
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }
        
        .device-model {
            background: #e9ecef;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 12px;
            color: #666;
        }
        
        .auth-key {
            background: #f1f3f5;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: monospace;
            word-break: break-all;
            font-size: 14px;
        }
        
        .key-label {
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            border-left: 4px solid #c33;
        }
        
        .success {
            background: #e8f8ef;
            color: #2b8a3e;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            border-left: 4px solid #2b8a3e;
        }
        
        .copy-btn {
            background: #4dabf7;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            font-size: 12px;
            cursor: pointer;
            margin-top: 5px;
            transition: background 0.3s;
        }
        
        .copy-btn:hover {
            background: #339af0;
        }
        
        .instructions {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
            font-size: 14px;
            color: #666;
        }
        
        .instructions h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .instructions ul {
            padding-left: 20px;
            margin: 10px 0;
        }
        
        .instructions li {
            margin-bottom: 8px;
        }
        
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin-top: 15px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 小米设备AuthKey获取工具</h1>
            <p>获取您的小米账号下所有智能设备的认证密钥</p>
        </div>
        
        <div class="card">
            <h2 style="margin-bottom: 20px; color: #333;">登录小米账号</h2>
            
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">小米账号（手机号/邮箱）</label>
                    <input type="text" id="username" name="username" required 
                           placeholder="请输入您的小米账号">
                </div>
                
                <div class="form-group">
                    <label for="password">密码</label>
                    <input type="password" id="password" name="password" required 
                           placeholder="请输入您的小米账号密码">
                </div>
                
                <div class="form-group">
                    <button type="submit" id="submitBtn">获取设备AuthKey</button>
                </div>
            </form>
            
            <div id="loading" class="loading" style="display: none;">
                <div style="font-size: 20px; margin-bottom: 10px;">⏳</div>
                <p>正在登录并获取设备信息，请稍候...</p>
                <p style="font-size: 14px; color: #666;">这可能需要30-60秒</p>
            </div>
            
            <div id="errorMessage" class="error" style="display: none;"></div>
            
            <div class="instructions">
                <h3>使用说明：</h3>
                <ul>
                    <li>请输入您的小米账号和密码进行登录</li>
                    <li>本工具仅用于获取设备的认证密钥，不会保存您的账号信息</li>
                    <li>获取的AuthKey可用于第三方智能家居集成</li>
                    <li>请确保您的设备已绑定到小米账号</li>
                </ul>
                <div class="warning">
                    <strong>⚠️ 安全提示：</strong> 请勿在公共网络环境下使用本工具，确保您信任此服务。
                </div>
            </div>
        </div>
        
        <div id="resultCard" class="card result-card">
            <h2 style="margin-bottom: 20px; color: #333;">设备AuthKey列表</h2>
            <div id="deviceCount" style="margin-bottom: 20px; color: #666;"></div>
            
            <div id="deviceList" class="device-list">
                <!-- 设备列表将在这里动态生成 -->
            </div>
            
            <div id="successMessage" class="success" style="display: none;"></div>
            
            <div style="text-align: center; margin-top: 30px;">
                <button onclick="location.reload()" style="width: auto; background: #868e96;">重新查询</button>
            </div>
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            const errorMessage = document.getElementById('errorMessage');
            const resultCard = document.getElementById('resultCard');
            
            // 显示加载状态
            submitBtn.disabled = true;
            submitBtn.textContent = '处理中...';
            loading.style.display = 'block';
            errorMessage.style.display = 'none';
            
            try {
                // 发送登录请求
                const response = await fetch('/get-devices', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // 显示结果
                    document.getElementById('deviceCount').innerHTML = 
                        `共找到 <strong>${result.devices.length}</strong> 个设备`;
                    
                    const deviceList = document.getElementById('deviceList');
                    deviceList.innerHTML = '';
                    
                    if (result.devices.length === 0) {
                        deviceList.innerHTML = '<div class="error">未找到任何设备，请确保设备已绑定到小米账号</div>';
                    } else {
                        result.devices.forEach((device, index) => {
                            const deviceItem = document.createElement('div');
                            deviceItem.className = 'device-item';
                            deviceItem.innerHTML = `
                                <div class="device-header">
                                    <div class="device-name">${device.device_name}</div>
                                    <div class="device-model">${device.model}</div>
                                </div>
                                <div class="device-info">
                                    <div style="margin-bottom: 5px;">
                                        <span style="color: #666;">设备ID:</span> ${device.device_id}
                                    </div>
                                    <div style="margin-bottom: 5px;">
                                        <span style="color: #666;">MAC地址:</span> ${device.mac_address}
                                    </div>
                                </div>
                                <div style="margin-top: 15px;">
                                    <div class="key-label">设备Token</div>
                                    <div class="auth-key">${device.token || '未获取到'}</div>
                                    ${device.token ? '<button class="copy-btn" onclick="copyToClipboard(\'' + device.token + '\')">
