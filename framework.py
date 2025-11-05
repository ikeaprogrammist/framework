import os
import sys
import requests
import phonenumbers
from phonenumbers import carrier, timezone, geocoder
import re
from urllib.parse import quote
import json
import socket
import whois
from datetime import datetime
import dns.resolver
import platform
import uuid
import hashlib

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}

GitHub -> 
Telegram -> @userskilling
Developer -> @angryscamer
Version -> 2.4   
                                                                                       
    ▄▄▄▄                                                                         ▄▄       
   ██▀▀▀                                                                         ██       
 ███████    ██▄████   ▄█████▄  ████▄██▄   ▄████▄  ██      ██  ▄████▄    ██▄████  ██ ▄██▀  
   ██       ██▀       ▀ ▄▄▄██  ██ ██ ██  ██▄▄▄▄██ ▀█  ██  █▀ ██▀  ▀██   ██▀      ██▄██    
   ██       ██       ▄██▀▀▀██  ██ ██ ██  ██▀▀▀▀▀▀  ██▄██▄██  ██    ██   ██       ██▀██▄   
   ██       ██       ██▄▄▄███  ██ ██ ██  ▀██▄▄▄▄█  ▀██  ██▀  ▀██▄▄██▀   ██       ██  ▀█▄  
   ▀▀       ▀▀        ▀▀▀▀ ▀▀  ▀▀ ▀▀ ▀▀    ▀▀▀▀▀    ▀▀  ▀▀     ▀▀▀▀     ▀▀       ▀▀   ▀▀▀ 
{Colors.END}
"""
    print(banner)

class HttpWebNumber:
    def __init__(self):
        self.__check_number_link = 'https://htmlweb.ru/geo/api.php?json&telcod='
        self.__not_found_text = 'Информация отсутствует'

    def __return_number_data(self, user_number):
        try:
            response = requests.get(self.__check_number_link + user_number,
                                    headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15'})
            if response.ok:
                return response.json()
            else:
                return {'status_error': True}
        except requests.exceptions.ConnectionError:
            return {'status_error': True}

    def get_number_data(self, user_number):
        return self.__return_number_data(user_number)

def get_additional_phone_info(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number, None)
        info = {}
        
        info['operator'] = carrier.name_for_number(parsed_number, "ru") or "Неизвестно"
        info['country'] = geocoder.country_name_for_number(parsed_number, "ru")
        info['timezones'] = timezone.time_zones_for_number(parsed_number)
        info['region'] = geocoder.description_for_number(parsed_number, "ru") or "Неизвестно"
        info['is_valid'] = phonenumbers.is_valid_number(parsed_number)
        info['is_possible'] = phonenumbers.is_possible_number(parsed_number)
        info['number_type'] = str(phonenumbers.number_type(parsed_number))
        
        number_types = {
            '0': 'FIXED_LINE',
            '1': 'MOBILE', 
            '2': 'FIXED_LINE_OR_MOBILE',
            '3': 'TOLL_FREE',
            '4': 'PREMIUM_RATE',
            '5': 'SHARED_COST',
            '6': 'VOIP',
            '7': 'PERSONAL_NUMBER',
            '8': 'PAGER',
            '9': 'UAN',
            '10': 'UNKNOWN'
        }
        info['number_type_name'] = number_types.get(info['number_type'], 'UNKNOWN')
        
        return info
    except:
        return {}

def phone_intelligence(phone_number):
    print(f"{Colors.YELLOW}╰ Начинаем расширенную разведку по номеру: {phone_number}{Colors.END}")
    
    try:
        api = HttpWebNumber()
        number_data = api.get_number_data(phone_number)
        
        not_found_text = 'Информация отсутствует'
        
        additional_info = get_additional_phone_info(phone_number)
        
        print(f"{Colors.GREEN}{Colors.BOLD}\n=РАСШИРЕННАЯ ИНФОРМАЦИЯ О НОМЕРЕ={Colors.END}")
        print(f"╰┈➤ Номер телефона: {phone_number}")
        print(f"╰┈➤ Валидность номера: {'Да' if additional_info.get('is_valid') else 'Нет'}")
        print(f"╰┈➤ Возможный номер: {'Да' if additional_info.get('is_possible') else 'Нет'}")
        print(f"╰┈➤ Тип номера: {additional_info.get('number_type_name', 'Неизвестно')}")
        
        if not number_data.get('status_error') and not number_data.get('error'):
            country = number_data.get('country', {})
            capital = number_data.get('capital', {})
            region = number_data.get('region', {})
            other = number_data.get('0', {})

            if country.get('country_code3') == 'UKR':
                print(f"╰┈➤ Страна: Украина")
            else:
                print(f"╰┈➤ Страна: {country.get('name', not_found_text)}")
            
            print(f"╰┈➤ Полное название страны: {country.get('fullname', not_found_text)}")
            print(f"╰┈➤ Столица: {capital.get('name', not_found_text)}")
            print(f"╰┈➤ Регион: {region.get('name', not_found_text)}")
            print(f"╰┈➤ Округ: {region.get('okrug', not_found_text)}")
            print(f"╰┈➤ Город: {other.get('name', not_found_text)}")
            print(f"╰┈➤ Почтовый индекс: {other.get('post', not_found_text)}")
            print(f"╰┈➤ Код валюты: {country.get('iso', not_found_text)}")
            print(f"╰┈➤ Телефонный код страны: {capital.get('telcod', not_found_text)}")
            print(f"╰┈➤ Автомобильный код региона: {region.get('autocod', not_found_text)}")
            print(f"╰┈➤ Оператор связи: {other.get('oper', not_found_text)}")
            print(f"╰┈➤ Бренд оператора: {other.get('oper_brand', not_found_text)}")
            print(f"╰┈➤ Локация: {number_data.get('location', not_found_text)}")
            print(f"╰┈➤ Язык: {country.get('lang', not_found_text)}")
            print(f"╰┈➤ Код языка: {country.get('langcod', not_found_text)}")
            print(f"╰┈➤ Широта: {other.get('latitude', not_found_text)}")
            print(f"╰┈➤ Долгота: {other.get('longitude', not_found_text)}")
            print(f"╰┈➤ Часовой пояс: {', '.join(additional_info.get('timezones', []))}")
            print(f"╰┈➤ Оператор (доп.): {additional_info.get('operator', 'Неизвестно')}")
            print(f"╰┈➤ Осталось запросов: {number_data.get('limit', not_found_text)}")

        print(f"{Colors.GREEN}{Colors.BOLD}\n=ПОИСК В ИНТЕРНЕТЕ={Colors.END}")
        search_engines = [
            ("Google", f"https://www.google.com/search?q={quote(phone_number)}"),
            ("Яндекс", f"https://yandex.ru/search/?text={quote(phone_number)}"),
            ("Bing", f"https://www.bing.com/search?q={quote(phone_number)}"),
            ("DuckDuckGo", f"https://duckduckgo.com/?q={quote(phone_number)}"),
            ("Mail.ru", f"https://go.mail.ru/search?q={quote(phone_number)}"),
        ]
        for name, url in search_engines:
            print(f"╰┈➤ {Colors.CYAN}{name} – {url}{Colors.END}")

        print(f"{Colors.GREEN}{Colors.BOLD}\n=СОЦИАЛЬНЫЕ СЕТИ И МЕССЕНДЖЕРЫ={Colors.END}")
        clean_number = phone_number.replace('+', '').replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        social_links = [
            ("Telegram", f"https://t.me/{clean_number}"),
            ("WhatsApp", f"https://wa.me/{clean_number}"),
            ("Viber", f"viber://chat?number={phone_number}"),
            ("Skype", f"skype:{phone_number}?call"),
            ("Instagram Direct", f"https://www.instagram.com/direct/t/{clean_number}"),
            ("Facebook Search", f"https://www.facebook.com/search/top/?q={phone_number}"),
            ("VK Search", f"https://vk.com/search?c%5Bphone%5D={clean_number}"),
            ("Одноклассники", f"https://ok.ru/search?st.query={clean_number}"),
            ("Twitter Search", f"https://twitter.com/search?q={phone_number}"),
            ("LinkedIn Search", f"https://www.linkedin.com/search/results/all/?keywords={phone_number}"),
        ]
        for platform, link in social_links:
            print(f"╰┈➤ {Colors.MAGENTA}{platform} – {link}{Colors.END}")

        print(f"{Colors.GREEN}{Colors.BOLD}\n=ПРОВЕРКА В БАЗАХ ДАННЫХ={Colors.END}")
        db_sources = [
            ("TrueCaller", f"https://www.truecaller.com/search/ru/{phone_number}"),
            ("Sync.me", f"https://sync.me/ru/{phone_number}"),
            ("NumVerify", f"https://numverify.com/"),
            ("SpyDialer", f"https://www.spydialer.com/default.aspx?phone={clean_number}"),
            ("Whitepages", f"https://www.whitepages.com/phone/{phone_number}"),
            ("CallerID Test", f"https://calleridtest.com/"),
            ("ZabaSearch", f"https://www.zabasearch.com/phone/{clean_number}"),
        ]
        for source, link in db_sources:
            print(f"╰┈➤ {Colors.YELLOW}{source} – {link}{Colors.END}")

        print(f"{Colors.GREEN}{Colors.BOLD}\n=ПРОВЕРКА НА УТЕЧКИ ДАННЫХ={Colors.END}")
        leak_sources = [
            ("Have I Been Pwned", "https://haveibeenpwned.com/"),
            ("DeHashed", "https://dehashed.com/"),
            ("LeakCheck", "https://leakcheck.io/"),
            ("Snusbase", "https://snusbase.com/"),
        ]
        for source, link in leak_sources:
            print(f"╰┈➤ {Colors.RED}{source} – {link}{Colors.END}")

        print(f"{Colors.GREEN}{Colors.BOLD}\n=БЫСТРЫЕ ДЕЙСТВИЯ={Colors.END}")
        print(f"╰┈➤ {Colors.RED}Позвонить – tel:{phone_number}{Colors.END}")
        print(f"╰┈➤ {Colors.BLUE}Отправить SMS – sms:{phone_number}{Colors.END}")
        print(f"╰┈➤ {Colors.GREEN}Добавить в контакты – contacts://{phone_number}{Colors.END}")
        print(f"╰┈➤ {Colors.MAGENTA}Скопировать номер – {phone_number}{Colors.END}")
        
    except Exception as e:
        print(f"{Colors.RED}╰┈➤ Ошибка: {str(e)}{Colors.END}")

def get_extended_ip_info(ip_address):
    try:
        info = {}
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            info['hostname'] = hostname
        except:
            info['hostname'] = "Не найден"
        
        try:
            whois_info = whois.whois(ip_address)
            info['whois'] = whois_info
        except:
            info['whois'] = {}
        
        info['ports'] = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    info['ports'].append(port)
                sock.close()
            except:
                pass
        
        return info
    except:
        return {}

def ip_intelligence(ip_address):
    print(f"{Colors.YELLOW}╰ Начинаем расширенную разведку по IP: {ip_address}{Colors.END}")
    
    try:
        ip_services = [
            {"name": "ipapi.co", "url": f"http://ipapi.co/{ip_address}/json/"},
            {"name": "ip-api.com", "url": f"http://ip-api.com/json/{ip_address}"},
            {"name": "ipinfo.io", "url": f"https://ipinfo.io/{ip_address}/json"},
        ]
        
        ip_data = {}
        for service in ip_services:
            try:
                response = requests.get(service['url'], timeout=10)
                if response.status_code == 200:
                    ip_data = response.json()
                    break
            except:
                continue

        extended_info = get_extended_ip_info(ip_address)
        
        print(f"{Colors.GREEN}{Colors.BOLD}\n=ОСНОВНАЯ ИНФОРМАЦИЯ={Colors.END}")
        print(f"╰┈➤ IP адрес: {ip_address}")
        print(f"╰┈➤ Имя хоста: {extended_info.get('hostname', 'Неизвестно')}")
        
        if ip_data:
            if 'city' in ip_data:
                print(f"╰┈➤ Город: {ip_data.get('city', 'Неизвестно')}")
            if 'region' in ip_data:
                print(f"╰┈➤ Регион: {ip_data.get('region', 'Неизвестно')}")
            if 'country' in ip_data:
                print(f"╰┈➤ Страна: {ip_data.get('country', 'Неизвестно')}")
            if 'country_name' in ip_data:
                print(f"╰┈➤ Страна: {ip_data.get('country_name', 'Неизвестно')}")
            if 'org' in ip_data:
                print(f"╰┈➤ Провайдер: {ip_data.get('org', 'Неизвестно')}")
            if 'isp' in ip_data:
                print(f"╰┈➤ Провайдер: {ip_data.get('isp', 'Неизвестно')}")
            if 'timezone' in ip_data:
                print(f"╰┈➤ Часовой пояс: {ip_data.get('timezone', 'Неизвестно')}")
            if 'lat' in ip_data and 'lon' in ip_data:
                print(f"╰┈➤ Координаты: {ip_data.get('lat', 'Неизвестно')}, {ip_data.get('lon', 'Неизвестно')}")
            if 'latitude' in ip_data and 'longitude' in ip_data:
                print(f"╰┈➤ Координаты: {ip_data.get('latitude', 'Неизвестно')}, {ip_data.get('longitude', 'Неизвестно')}")
            if 'postal' in ip_data:
                print(f"╰┈➤ Почтовый индекс: {ip_data.get('postal', 'Неизвестно')}")
            if 'zip' in ip_data:
                print(f"╰┈➤ Почтовый индекс: {ip_data.get('zip', 'Неизвестно')}")

        print(f"{Colors.GREEN}{Colors.BOLD}\n=ТЕХНИЧЕСКАЯ ИНФОРМАЦИЯ={Colors.END}")
        if extended_info['ports']:
            print(f"╰┈➤ Открытые порты: {', '.join(map(str, extended_info['ports']))}")
        else:
            print(f"╰┈➤ Открытые порты: не обнаружены")

        print(f"{Colors.GREEN}{Colors.BOLD}\n=ОНЛАЙН ПРОВЕРКИ={Colors.END}")
        check_sources = [
            ("Shodan", f"https://www.shodan.io/host/{ip_address}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip_address}"),
            ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip_address}"),
            ("GreyNoise", f"https://viz.greynoise.io/ip/{ip_address}"),
            ("URLScan", f"https://urlscan.io/ip/{ip_address}"),
            ("Whois", f"https://whois.domaintools.com/{ip_address}"),
            ("IPVoid", f"https://www.ipvoid.com/scan/{ip_address}"),
            ("ThreatCrowd", f"https://www.threatcrowd.org/ip.php?ip={ip_address}"),
        ]
        for source, link in check_sources:
            print(f"╰┈➤ {Colors.MAGENTA}{source} – {link}{Colors.END}")

    except Exception as e:
        print(f"{Colors.RED}╰┈➤ Ошибка: {str(e)}{Colors.END}")

def universal_intelligence():
    print(f"{Colors.YELLOW}╰ Начинаем универсальную разведку{Colors.END}")
    target = input(f"{Colors.CYAN}╰ Введите данные для поиска (email, имя, username, домен): {Colors.END}")
    
    if not target:
        return
    
    print(f"{Colors.GREEN}{Colors.BOLD}\n=БАЗОВЫЙ ПОИСК={Colors.END}")
    
    basic_search = [
        ("Google", f"https://www.google.com/search?q={quote(target)}"),
        ("Яндекс", f"https://yandex.ru/search/?text={quote(target)}"),
        ("Bing", f"https://www.bing.com/search?q={quote(target)}"),
        ("DuckDuckGo", f"https://duckduckgo.com/?q={quote(target)}"),
    ]
    
    for name, url in basic_search:
        print(f"╰┈➤ {Colors.CYAN}{name} – {url}{Colors.END}")
    
    if '@' in target:
        print(f"{Colors.GREEN}{Colors.BOLD}\n=ПОИСК ПО EMAIL={Colors.END}")
        email_searches = [
            ("Have I Been Pwned", f"https://haveibeenpwned.com/account/{quote(target)}"),
            ("Hunter.io", f"https://hunter.io/verify/{quote(target)}"),
            ("EmailRep", f"https://emailrep.io/{quote(target)}"),
            ("DeHashed", f"https://dehashed.com/search?query={quote(target)}"),
        ]
        for platform, link in email_searches:
            print(f"╰┈➤ {Colors.MAGENTA}{platform} – {link}{Colors.END}")
    
    elif '.' in target and ' ' not in target:
        print(f"{Colors.GREEN}{Colors.BOLD}\n=ПОИСК ПО ДОМЕНУ={Colors.END}")
        domain_searches = [
            ("Whois", f"https://whois.domaintools.com/{quote(target)}"),
            ("SecurityTrails", f"https://securitytrails.com/domain/{quote(target)}"),
            ("Shodan", f"https://www.shodan.io/search?query=hostname:{quote(target)}"),
            ("VirusTotal", f"https://www.virustotal.com/gui/domain/{quote(target)}"),
            ("DNSDumpster", f"https://dnsdumpster.com/"),
            ("BuiltWith", f"https://builtwith.com/{quote(target)}"),
        ]
        for platform, link in domain_searches:
            print(f"╰┈➤ {Colors.YELLOW}{platform} – {link}{Colors.END}")
    
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}\n=ПОИСК ПО ИМЕНИ И USERNAME={Colors.END}")
        username_searches = [
            ("Facebook", f"https://www.facebook.com/{quote(target)}"),
            ("Instagram", f"https://www.instagram.com/{quote(target)}"),
            ("Twitter", f"https://twitter.com/{quote(target)}"),
            ("VK", f"https://vk.com/{quote(target)}"),
            ("GitHub", f"https://github.com/{quote(target)}"),
            ("Telegram", f"https://t.me/{quote(target)}"),
            ("Reddit", f"https://www.reddit.com/user/{quote(target)}"),
            ("Steam", f"https://steamcommunity.com/id/{quote(target)}"),
        ]
        for platform, link in username_searches:
            print(f"╰┈➤ {Colors.BLUE}{platform} – {link}{Colors.END}")
    
    print(f"{Colors.GREEN}{Colors.BOLD}\n=СОЦИАЛЬНЫЕ СЕТИ={Colors.END}")
    social_networks = [
        ("Facebook Search", f"https://www.facebook.com/search/top/?q={quote(target)}"),
        ("Instagram Search", f"https://www.instagram.com/web/search/top/search/?query={quote(target)}"),
        ("Twitter Search", f"https://twitter.com/search?q={quote(target)}"),
        ("VK Search", f"https://vk.com/search?c%5Bq%5D={quote(target)}"),
        ("LinkedIn Search", f"https://www.linkedin.com/search/results/all/?keywords={quote(target)}"),
        ("YouTube Search", f"https://www.youtube.com/results?search_query={quote(target)}"),
        ("TikTok Search", f"https://www.tiktok.com/search?q={quote(target)}"),
    ]
    
    for platform, link in social_networks:
        print(f"╰┈➤ {Colors.MAGENTA}{platform} – {link}{Colors.END}")

def main_menu():
    while True:
        clear_screen()
        print_banner()
        
        menu = f"""
{Colors.GREEN}{Colors.BOLD}
╰ 1 – Разведка по номеру телефона
╰ 2 – Расширенная разведка по IP адресу
╰ 3 – Расширенная универсальная разведка
╰ 4 – Выход из программы
{Colors.END}

{Colors.YELLOW}Выберите опцию >{Colors.END}"""
        
        choice = input(menu)
        
        if choice == '1':
            phone = input(f"{Colors.CYAN}╰ Введите номер телефона (с кодом страны): {Colors.END}")
            if phone:
                phone_intelligence(phone)
                input(f"\n{Colors.YELLOW}Нажмите Enter для продолжения...{Colors.END}")
        
        elif choice == '2':
            ip = input(f"{Colors.CYAN}╰ Введите IP адрес: {Colors.END}")
            if ip:
                ip_intelligence(ip)
                input(f"\n{Colors.YELLOW}Нажмите Enter для продолжения...{Colors.END}")
        
        elif choice == '3':
            universal_intelligence()
            input(f"\n{Colors.YELLOW}Нажмите Enter для продолжения...{Colors.END}")
        
        elif choice == '4':
            print(f"{Colors.RED}Выход из программы...{Colors.END}")
            break
        
        else:
            print(f"{Colors.RED}Неверный выбор! Попробуйте снова.{Colors.END}")
            input(f"{Colors.YELLOW}Нажмите Enter для продолжения...{Colors.END}")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Программа прервана пользователем.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Критическая ошибка: {str(e)}{Colors.END}")