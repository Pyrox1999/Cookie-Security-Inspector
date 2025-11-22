import os
os.environ['SDL_VIDEO_WINDOW_POS'] = '100,100'
import random
import pgzrun
import pygame
import requests
from urllib.parse import urlparse
from datetime import datetime
import re

random.seed()

pygame.mixer.music.load("song.ogg") #glitchart
pygame.mixer.music.play(-1)

level = -1
target = "127.0.0.1"
message=""
gemacht=False

class CookieInspector:
    def __init__(self):
        self.issues = []
        self.score = 100
        
    def analyze_url(self, url):
        global message
        message+=f"\n{'='*60}\n"
        message+=f"Cookie Security Analysis for: {url}\n"
        message+=f"{'='*60}\n"
        
        try:
            response = requests.get(url, timeout=10)
            cookies = response.cookies
            
            if not cookies:
                message+="⚠️  No Cookies found!\n"
                return
            
            message+=f"✓ {len(cookies)} Cookie(s) found\n"
            
            for cookie in cookies:
                self.analyze_cookie(cookie, url)
                
            self.print_summary()
            
        except requests.RequestException as e:
            message+=f"❌ Error on calling URL: {e}\n"
    
    def analyze_cookie(self, cookie, url):
        global message
        message+=f"\n{'─'*60}\n"
        message+=f"🍪 Cookie: {cookie.name}\n"
        message+=f"{'─'*60}\n"
        message+=f"Value: {cookie.value[:50]}{'...' if len(cookie.value) > 50 else ''}\n"
        message+=f"Domain: {cookie.domain or 'Not set'}\n"
        message+=f"Path: {cookie.path or '/'}\n"
        
        
        issues = []
        
        
        if cookie.has_nonstandard_attr('HttpOnly'):
            message+="✓ HttpOnly: Yes\n"
        else:
            message+="❌ HttpOnly: NO - vulnerable for XSS-Attacks!\n"
            issues.append("HttpOnly missing")
            self.score -= 15
        
        
        if cookie.secure:
            message+="✓ Secure: Yes\n"
        else:
            message+="❌ Secure: NO - Cookie can be transported with HTTP!\n"
            issues.append("Secure-Flag missing")
            self.score -= 15
        
        
        samesite = None
        for key in cookie._rest.keys():
            if key.lower() == 'samesite':
                samesite = cookie._rest[key]
                break
        
        if samesite:
            message+=f"✓ SameSite: {samesite}\n"
            if samesite.lower() == 'none' and not cookie.secure:
                message+="  ⚠️  SameSite=None requires Secure-Flag!\n"
                issues.append("SameSite=None without Secure")
                self.score -= 10
        else:
            message+="⚠️  SameSite: Not set - vulnerable for CSRF!\n"
            issues.append("SameSite not set")
            self.score -= 10
        
        
        if cookie.expires:
            exp_date = datetime.fromtimestamp(cookie.expires)
            days_valid = (exp_date - datetime.now()).days
            message+=f"Expires: {exp_date.strftime('%Y-%m-%d %H:%M:%S')} ({days_valid} days)\n"
            
            if days_valid > 365:
                message+="  ⚠️  Cookie is longer than one year valid\n"
                issues.append(f"too longe lifetime ({days_valid} dyas)")
                self.score -= 5
        else:
            message+="Expires: Session-Cookie (will be deleted when closed)\n"
        
        
        parsed_url = urlparse(url)
        if cookie.domain and cookie.domain.startswith('.'):
            message+=f"  ⚠️  Domain begins with '.' - is for all subdomains!\n"
            issues.append("To continue Domain-Scope")
            self.score -= 5
        
        
        size = len(cookie.name) + len(cookie.value)
        message+=f"Size: {size} Bytes\n"
        if size > 4096:
            message+="  ⚠️  Cookie ist very big (>4KB)!\n"
            issues.append("Very big Cookie-Size")
            self.score -= 3
        
        
        sensitive_keywords = ['session', 'token', 'auth', 'jwt', 'password', 'secret']
        if any(keyword in cookie.name.lower() for keyword in sensitive_keywords):
            message+="⚠️  WARNING: Cookie seems to contain sensible data!\n"
            if not cookie.has_nonstandard_attr('HttpOnly') or not cookie.secure:
                message+="  ❌ CRITICAL: Sensitive data without enough protection!\n"
                self.score -= 20
        
        
        if issues:
            self.issues.append({
                'cookie': cookie.name,
                'issues': issues
            })
    
    def print_summary(self):
        global message
        message+=f"\n\n{'='*60}\n"
        message+="📊 SECURITY SCORE\n"
        message+=f"{'='*60}\n"
        
        
        final_score = max(0, self.score)
        
        
        if final_score >= 90:
            rating = "🟢 VERY GOOD"
        elif final_score >= 70:
            rating = "🟡 GOOD"
        elif final_score >= 50:
            rating = "🟠 MEDIUM"
        else:
            rating = "🔴 BAD"
        
        print(f"\nFinal Score: {final_score}/100 - {rating}\n")
        
        if self.issues:
            message+="⚠️  FOUND PROBLEMS:\n"
            for item in self.issues:
                message+=f"\n  Cookie: {item['cookie']}\n"
                for issue in item['issues']:
                    message+=f"    • {issue}\n"
        else:
            message+="✓ No security-problems found!\n"
        
        message+=f"\n{'='*60}\n"
    
    def reset(self):
        
        self.issues = []
        self.score = 100


def haupt(url2):
    global message
    
    inspector = CookieInspector()
    
    
    test_urls = [
        "http://localhost",  
        
    ]
    
    message+="Test localhost (starts before a local web-server)\n"
    message+="Or enter another URL:\n"
    
    url = url2
    
    if not url:
        url = "http://localhost"
    
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    inspector.analyze_url(url)
    
    
def draw():
    global level, target,message
    screen.clear()
    if level == -1:
        screen.blit("title", (0, 0))
    elif level == 0:
        screen.blit("intro", (0, 0))
    elif level == 1:
        screen.blit("back", (0, 0))
        screen.draw.text("Website with cookie to check (RETURN=localhost):", center=(400, 130), fontsize=24, color=(25, 200, 255))
        screen.draw.text(target, center=(400, 180), fontsize=24, color=(255, 255, 0))
    elif level == 2:
        screen.blit("back", (0, 0))
        screen.draw.text(message, center=(400, 280), fontsize=24, color=(255, 255, 0))
        
def on_key_down(key, unicode=None):
    global level, target
    if key==keys.ESCAPE:
        pygame.quit()
    if key == keys.BACKSPACE:
        target = ""
    elif key == keys.RETURN and level == 1:
        
        level = 2
    elif unicode and key != keys.RETURN and level==1:
        target += unicode

def update():
    global level,target,inspector,gemacht
    if (level == 0 or level==-2) and keyboard.RETURN:
        level +=1
    elif level -1 and keyboard.space:
        level = 0
    if level==1:
        pass
    if level==2:
        if not gemacht:
            haupt(target)
            gemacht=True
        if keyboard.space:
            level=0


pgzrun.go()
