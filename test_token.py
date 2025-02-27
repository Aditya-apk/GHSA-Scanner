import requests
import os
from dotenv import load_dotenv

load_dotenv()

headers = {
    "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}"
}

# Test the GraphQL API
query = """
query {
  viewer {
    login
  }
}
"""

response = requests.post(
    'https://api.github.com/graphql',
    json={'query': query},
    headers=headers
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")