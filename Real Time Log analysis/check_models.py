import google.generativeai as genai
import os
import sys

# Try to get key from env or file
api_key = os.getenv('GEMINI_API_KEY') or os.getenv('GEMINI_API')
if not api_key and os.path.exists("api_key.txt"):
    try:
        with open("api_key.txt", "r") as f:
            content = f.read().strip()
            if content and "PASTE" not in content:
                api_key = content
    except:
        pass

if not api_key:
    # Fallback to command line
    if len(sys.argv) > 1:
        api_key = sys.argv[1]
    else:
        print("Error: No API Key found.")
        sys.exit(1)

genai.configure(api_key=api_key)

print("Listing available models...")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(m.name)
except Exception as e:
    print(f"Error listing models: {e}")
