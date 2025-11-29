#!/usr/bin/env python3
"""
Download and generate diverse safe data for ML training.

Sources:
- Names: randomuser.me, common names lists
- Dictionary: English words
- Lorem Ipsum: Generated paragraphs
- Real-world patterns: Emails, phones, addresses, etc.
"""

import os
import json
import random
import string
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data" / "samples"
SAFE_FILE = DATA_DIR / "safe_diverse.txt"

# ═══════════════════════════════════════════════════════════════════
# Download functions
# ═══════════════════════════════════════════════════════════════════

def download_english_words():
    """Download English dictionary words."""
    print("📚 Downloading English dictionary...")
    url = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            words = response.read().decode('utf-8').strip().split('\n')
            # Filter reasonable length words
            words = [w.strip() for w in words if 3 <= len(w.strip()) <= 15]
            print(f"   Downloaded {len(words)} words")
            return words[:50000]  # Limit to 50k
    except Exception as e:
        print(f"   Error: {e}")
        return []

def download_common_names():
    """Download common first and last names."""
    print("👤 Downloading common names...")
    names = []
    
    # First names
    first_url = "https://raw.githubusercontent.com/dominictarr/random-name/master/first-names.txt"
    try:
        with urllib.request.urlopen(first_url, timeout=30) as response:
            first_names = response.read().decode('utf-8').strip().split('\n')
            first_names = [n.strip() for n in first_names if n.strip()]
            print(f"   Downloaded {len(first_names)} first names")
            names.extend(first_names[:5000])
    except Exception as e:
        print(f"   First names error: {e}")
    
    # Last names
    last_url = "https://raw.githubusercontent.com/dominictarr/random-name/master/last-names.txt"
    try:
        with urllib.request.urlopen(last_url, timeout=30) as response:
            last_names = response.read().decode('utf-8').strip().split('\n')
            last_names = [n.strip() for n in last_names if n.strip()]
            print(f"   Downloaded {len(last_names)} last names")
            names.extend(last_names[:5000])
    except Exception as e:
        print(f"   Last names error: {e}")
    
    return names

def download_cities():
    """Download city names."""
    print("🌆 Downloading city names...")
    url = "https://raw.githubusercontent.com/datasets/world-cities/master/data/world-cities.csv"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            lines = response.read().decode('utf-8').strip().split('\n')[1:]  # Skip header
            cities = []
            for line in lines[:10000]:
                parts = line.split(',')
                if parts:
                    cities.append(parts[0].strip('"'))
            print(f"   Downloaded {len(cities)} cities")
            return cities
    except Exception as e:
        print(f"   Error: {e}")
        return []

# ═══════════════════════════════════════════════════════════════════
# Generate functions
# ═══════════════════════════════════════════════════════════════════

def generate_emails(count=5000):
    """Generate realistic email addresses."""
    print(f"📧 Generating {count} emails...")
    domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 
               'protonmail.com', 'mail.com', 'example.com', 'company.com', 'work.org']
    first_names = ['john', 'jane', 'bob', 'alice', 'mike', 'sarah', 'david', 'emma', 
                   'chris', 'lisa', 'tom', 'mary', 'james', 'anna', 'peter', 'kate']
    last_names = ['smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller',
                  'davis', 'rodriguez', 'martinez', 'wilson', 'anderson', 'taylor']
    
    emails = []
    for _ in range(count):
        first = random.choice(first_names)
        last = random.choice(last_names)
        domain = random.choice(domains)
        sep = random.choice(['.', '_', ''])
        num = random.choice(['', str(random.randint(1, 999)), str(random.randint(80, 99))])
        emails.append(f"{first}{sep}{last}{num}@{domain}")
    return emails

def generate_phone_numbers(count=3000):
    """Generate phone numbers in various formats."""
    print(f"📱 Generating {count} phone numbers...")
    formats = [
        "+1 ({0}) {1}-{2}",
        "+1-{0}-{1}-{2}",
        "({0}) {1}-{2}",
        "{0}.{1}.{2}",
        "+84 {0} {1} {2}",
        "+44 {0} {1} {2}",
        "+81 {0}-{1}-{2}",
        "+49 {0} {1} {2}",
        "1-800-{1}-{2}",
    ]
    phones = []
    for _ in range(count):
        fmt = random.choice(formats)
        area = str(random.randint(200, 999))
        pre = str(random.randint(200, 999))
        line = str(random.randint(1000, 9999))
        phones.append(fmt.format(area, pre, line))
    return phones

def generate_addresses(count=3000):
    """Generate street addresses."""
    print(f"🏠 Generating {count} addresses...")
    streets = ['Main St', 'Oak Ave', 'Elm St', 'Park Rd', 'First Ave', 'Second St',
               'Third Ave', 'Fourth St', 'Fifth Ave', 'Broadway', 'Market St',
               'Washington Blvd', 'Lincoln Way', 'Jefferson Dr', 'Madison Ave']
    types = ['St', 'Ave', 'Rd', 'Blvd', 'Dr', 'Way', 'Ln', 'Ct', 'Pl']
    units = ['', ', Apt {0}', ', Suite {0}', ', Unit {0}', ', Floor {0}', ', #{0}']
    
    addresses = []
    for _ in range(count):
        num = random.randint(1, 9999)
        street = random.choice(streets)
        unit = random.choice(units)
        if unit:
            unit = unit.format(random.choice([random.randint(1, 50), 
                                              random.choice('ABCDEF') + str(random.randint(1, 9))]))
        addresses.append(f"{num} {street}{unit}")
    return addresses

def generate_sentences(words, count=10000):
    """Generate random sentences from word list."""
    print(f"📝 Generating {count} sentences...")
    if not words:
        return []
    
    sentences = []
    templates = [
        "The {0} is very {1}",
        "I need to {0} the {1}",
        "Please {0} this {1}",
        "Can you {0} the {1}?",
        "We should {0} {1} {2}",
        "This is a {0} {1}",
        "How to {0} {1}?",
        "Why does {0} {1}?",
        "I love {0} and {1}",
        "The {0} {1} is great",
        "{0} {1} {2} {3}",
        "My {0} is {1}",
        "Your {0} looks {1}",
        "Their {0} seems {1}",
        "Our {0} needs {1}",
    ]
    
    for _ in range(count):
        template = random.choice(templates)
        num_words = template.count('{')
        selected = random.sample(words, min(num_words, len(words)))
        try:
            sentences.append(template.format(*selected))
        except:
            sentences.append(' '.join(random.sample(words, random.randint(3, 8))))
    
    return sentences

def generate_file_paths(count=3000):
    """Generate realistic file paths."""
    print(f"📁 Generating {count} file paths...")
    unix_dirs = ['/home/user', '/var/www', '/tmp', '/opt', '/usr/local', 
                 '~', '.', '..', './src', './lib', './app']
    win_dirs = ['C:/Users/John', 'C:/Program Files', 'D:/Projects', 
                'C:/Windows/Temp', 'C:/Documents']
    folders = ['documents', 'images', 'downloads', 'music', 'videos',
               'projects', 'work', 'backup', 'data', 'config', 'assets',
               'src', 'lib', 'components', 'utils', 'models', 'views']
    extensions = ['.txt', '.pdf', '.doc', '.docx', '.jpg', '.png', '.gif',
                  '.mp3', '.mp4', '.zip', '.json', '.xml', '.csv', '.xlsx',
                  '.js', '.ts', '.py', '.java', '.cpp', '.html', '.css']
    
    paths = []
    for _ in range(count):
        if random.random() < 0.7:  # Unix
            base = random.choice(unix_dirs)
            folder = random.choice(folders)
            file = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 12)))
            ext = random.choice(extensions)
            paths.append(f"{base}/{folder}/{file}{ext}")
        else:  # Windows
            base = random.choice(win_dirs)
            folder = random.choice(folders)
            file = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 12)))
            ext = random.choice(extensions)
            paths.append(f"{base}/{folder}/{file}{ext}")
    
    return paths

def generate_urls(count=3000):
    """Generate safe URLs."""
    print(f"🌐 Generating {count} URLs...")
    domains = ['example.com', 'mysite.com', 'company.org', 'shop.com',
               'blog.net', 'news.com', 'app.io', 'service.co', 'api.dev']
    paths = ['', '/about', '/contact', '/products', '/services', '/blog',
             '/api/v1', '/users', '/items', '/search', '/help', '/faq']
    
    urls = []
    for _ in range(count):
        protocol = random.choice(['http://', 'https://'])
        subdomain = random.choice(['', 'www.', 'api.', 'app.', 'cdn.', 'img.'])
        domain = random.choice(domains)
        path = random.choice(paths)
        
        # Add query params sometimes
        query = ''
        if random.random() < 0.3:
            params = []
            for _ in range(random.randint(1, 3)):
                key = random.choice(['page', 'id', 'q', 'sort', 'limit', 'offset', 'lang'])
                val = random.choice([str(random.randint(1, 100)), 'asc', 'desc', 'en', 'vi'])
                params.append(f"{key}={val}")
            query = '?' + '&'.join(params)
        
        urls.append(f"{protocol}{subdomain}{domain}{path}{query}")
    
    return urls

def generate_json_objects(count=2000):
    """Generate safe JSON-like strings."""
    print(f"📋 Generating {count} JSON objects...")
    objects = []
    
    keys = ['name', 'id', 'email', 'status', 'type', 'value', 'count', 
            'title', 'description', 'created', 'updated', 'active']
    values = ['test', 'user', 'active', 'pending', 'done', 'new', 'old',
              'primary', 'secondary', 'default', 'custom']
    
    for _ in range(count):
        obj = {}
        for _ in range(random.randint(1, 4)):
            key = random.choice(keys)
            if random.random() < 0.5:
                obj[key] = random.choice(values)
            else:
                obj[key] = random.randint(1, 1000)
        objects.append(json.dumps(obj))
    
    return objects

def generate_common_messages(count=5000):
    """Generate common chat/comment messages."""
    print(f"💬 Generating {count} messages...")
    
    templates = [
        "Thanks for your help!",
        "Great work everyone!",
        "Can you please check this?",
        "I'll look into it",
        "Sounds good to me",
        "Let me know if you need anything",
        "I'm working on it now",
        "Should be done by tomorrow",
        "Just finished the task",
        "Please review when you have time",
        "I have a question about this",
        "Could you explain more?",
        "I agree with your suggestion",
        "Let's discuss in the meeting",
        "Happy to help!",
        "No problem at all",
        "I'll get back to you soon",
        "Thanks for the update",
        "Looking forward to it",
        "See you tomorrow",
        "Have a great day!",
        "Good morning team",
        "Good afternoon everyone",
        "Hope you're doing well",
        "Best regards",
        "Kind regards",
        "Cheers!",
        "Talk soon",
        "Take care",
        "All the best",
    ]
    
    messages = []
    for _ in range(count):
        msg = random.choice(templates)
        # Add emoji sometimes
        if random.random() < 0.2:
            emoji = random.choice(['👍', '😊', '🎉', '✅', '💪', '🙏', '❤️', '😄'])
            msg = f"{msg} {emoji}"
        messages.append(msg)
    
    return messages

def generate_product_names(count=2000):
    """Generate product-like names."""
    print(f"📦 Generating {count} product names...")
    
    adjectives = ['Ultra', 'Pro', 'Max', 'Plus', 'Lite', 'Mini', 'Super',
                  'Premium', 'Elite', 'Basic', 'Advanced', 'Smart', 'Quick']
    nouns = ['Phone', 'Laptop', 'Watch', 'Camera', 'Speaker', 'Tablet',
             'TV', 'Monitor', 'Keyboard', 'Mouse', 'Headphones', 'Charger']
    
    products = []
    for _ in range(count):
        adj = random.choice(adjectives)
        noun = random.choice(nouns)
        version = random.choice(['', ' 2', ' 3', ' X', ' S', ' SE', ' Pro'])
        year = random.choice(['', ' 2024', ' 2025'])
        products.append(f"{adj} {noun}{version}{year}")
    
    return products

# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  DOWNLOADING & GENERATING DIVERSE SAFE DATA")
    print("=" * 60)
    print()
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    all_safe = []
    
    # Download external data
    words = download_english_words()
    names = download_common_names()
    cities = download_cities()
    
    # Add downloaded data
    if words:
        all_safe.extend(random.sample(words, min(10000, len(words))))
    if names:
        all_safe.extend(random.sample(names, min(5000, len(names))))
    if cities:
        all_safe.extend(random.sample(cities, min(3000, len(cities))))
    
    # Generate synthetic data
    all_safe.extend(generate_emails(5000))
    all_safe.extend(generate_phone_numbers(3000))
    all_safe.extend(generate_addresses(3000))
    all_safe.extend(generate_sentences(words, 10000))
    all_safe.extend(generate_file_paths(3000))
    all_safe.extend(generate_urls(3000))
    all_safe.extend(generate_json_objects(2000))
    all_safe.extend(generate_common_messages(5000))
    all_safe.extend(generate_product_names(2000))
    
    # Deduplicate and filter
    all_safe = list(set(all_safe))
    all_safe = [s for s in all_safe if s and len(s) >= 3]
    
    # Shuffle
    random.shuffle(all_safe)
    
    # Save
    with open(SAFE_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Diverse safe data - {len(all_safe)} samples\n")
        for item in all_safe:
            f.write(f"{item}\n")
    
    print()
    print("=" * 60)
    print(f"✅ Saved {len(all_safe)} diverse safe samples to:")
    print(f"   {SAFE_FILE}")
    print("=" * 60)

if __name__ == "__main__":
    main()
