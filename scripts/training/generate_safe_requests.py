#!/usr/bin/env python3
"""
Generate synthetic safe requests for training.

Creates realistic API requests that are NOT attacks.

Usage:
    python3 generate_safe_requests.py --count 50000
"""

import argparse
import random
from pathlib import Path

# Common API paths - include auth paths heavily
API_PATHS = [
    '/api/users', '/api/products', '/api/orders', 
    '/api/auth/login', '/api/auth/logout', '/api/auth/register',
    '/api/auth/refresh', '/api/auth/verify', '/api/auth/reset-password',
    '/api/auth/forgot-password', '/api/auth/change-password',
    '/api/login', '/api/logout', '/api/register', '/api/signin', '/api/signup',
    '/api/profile', '/api/settings', '/api/notifications', '/api/messages',
    '/api/search', '/api/categories', '/api/items', '/api/cart',
    '/api/checkout', '/api/payments', '/api/subscriptions',
    '/api/comments', '/api/reviews', '/api/ratings', '/api/favorites',
    '/api/history', '/api/analytics', '/api/reports', '/api/dashboard',
    '/api/v1/users', '/api/v2/products', '/api/v1/health',
    '/api/v1/auth/login', '/api/v1/auth/register',
    '/health', '/status', '/metrics', '/ready', '/live',
    '/oauth/token', '/oauth/authorize', '/oauth/callback',
    '/session', '/token', '/verify',
]

# Common query params
QUERY_PARAMS = {
    'page': lambda: random.randint(1, 100),
    'limit': lambda: random.choice([10, 20, 50, 100]),
    'offset': lambda: random.randint(0, 1000),
    'sort': lambda: random.choice(['asc', 'desc', 'created_at', 'updated_at', 'name', 'price']),
    'order': lambda: random.choice(['asc', 'desc']),
    'filter': lambda: random.choice(['active', 'pending', 'completed', 'all']),
    'status': lambda: random.choice(['active', 'inactive', 'pending', 'approved']),
    'type': lambda: random.choice(['user', 'admin', 'guest', 'premium']),
    'category': lambda: random.choice(['electronics', 'clothing', 'food', 'books', 'sports']),
    'q': lambda: random.choice(['hello', 'world', 'search term', 'product name', 'user query']),
    'id': lambda: random.randint(1, 999999),
    'userId': lambda: random.randint(1, 99999),
    'productId': lambda: random.randint(1, 99999),
    'lang': lambda: random.choice(['en', 'vi', 'ja', 'ko', 'zh']),
    'locale': lambda: random.choice(['en-US', 'vi-VN', 'ja-JP']),
}

# Common request bodies - include auth patterns to reduce false positives
BODY_TEMPLATES = [
    'username={name}&password=***',
    'username={name}&password=secret123',
    'username={name}&password=mypassword',
    'email={email}&password=***',
    'login={name}&pass={name}123',
    'user={name}&pwd=***',
    'email={email}&name={name}',
    'title={title}&content={content}',
    'quantity={num}&productId={id}',
    'rating={rating}&comment={comment}',
    'page={page}&status=active',
    'token=abc123xyz&refresh=true',
    'session_id=xyz789&user_id={id}',
    'api_key=sk_live_xxx&action=verify',
]

NAMES = ['john', 'jane', 'bob', 'alice', 'mike', 'sarah', 'david', 'emma']
EMAILS = ['user@example.com', 'test@test.com', 'admin@company.com']
TITLES = ['My Post', 'Hello World', 'Test Title', 'New Product']
CONTENTS = ['This is content', 'Hello there', 'Sample text', 'Description here']
COMMENTS = ['Great product', 'Very nice', 'Recommended', 'Good quality']

METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']


def generate_query_string() -> str:
    """Generate random query parameters."""
    num_params = random.randint(0, 4)
    if num_params == 0:
        return ''
    
    params = random.sample(list(QUERY_PARAMS.keys()), num_params)
    pairs = [f"{p}={QUERY_PARAMS[p]()}" for p in params]
    return '?' + '&'.join(pairs)


def generate_body() -> str:
    """Generate random request body."""
    if random.random() > 0.3:
        return ''
    
    template = random.choice(BODY_TEMPLATES)
    return template.format(
        name=random.choice(NAMES),
        email=random.choice(EMAILS),
        title=random.choice(TITLES),
        content=random.choice(CONTENTS),
        comment=random.choice(COMMENTS),
        num=random.randint(1, 10),
        id=random.randint(1, 9999),
        rating=random.randint(1, 5),
        page=random.randint(1, 10),
    )


def generate_request() -> str:
    """Generate a single safe request."""
    method = random.choice(METHODS)
    path = random.choice(API_PATHS)
    
    # Add ID to path sometimes
    if random.random() > 0.5 and '{id}' not in path:
        path = path + '/' + str(random.randint(1, 9999))
    
    query = generate_query_string()
    body = generate_body() if method in ['POST', 'PUT', 'PATCH'] else ''
    
    request = f"{method} {path}{query}"
    if body:
        request += f" {body}"
    
    return request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=50000, help='Number of samples')
    parser.add_argument('--output', default='data/samples/safe.txt', help='Output file')
    args = parser.parse_args()
    
    output_path = Path(__file__).parent / args.output
    
    print(f"Generating {args.count} safe requests...")
    
    requests = set()
    while len(requests) < args.count:
        requests.add(generate_request())
        if len(requests) % 10000 == 0:
            print(f"  Generated {len(requests)}...")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# Auto-generated safe requests\n")
        f.write(f"# Total: {len(requests)}\n\n")
        for req in requests:
            f.write(req + '\n')
    
    print(f"\n✅ Written {len(requests)} safe requests to {output_path}")


if __name__ == '__main__':
    main()
