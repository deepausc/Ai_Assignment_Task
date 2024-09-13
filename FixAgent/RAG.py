import openai
import configparser

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')

OPENAI_API_KEY = config.get('openai', 'OPENAI_API_KEY')

# Generate context for LLM
def generate_context(vulnerability_id, description):
    # Construct a simple context with given information
    context = f"Vulnerability ID: {vulnerability_id}\nDescription: {description}\n"
    return context

# Generate response using OpenAI API (using chat model)
def generate_sbom_response(query, context):
    # Customize the prompt to request specific information
    messages = [
        {"role": "system", "content": "You are an assistant that helps with software security advisories."},
        {"role": "user", "content": f"Given the following SBOM data:\n{context}\nPlease provide detailed recommendations for mitigating the identified vulnerabilities."}
    ]
    
    openai.api_key = OPENAI_API_KEY
    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=messages,
        max_tokens=300  # Increased token limit for detailed response
    )
    return response.choices[0].message['content'].strip()

# Generate a fix plan using LLM when no data is found
def generate_fix_plan(vulnerability_id, description):
    prompt = f"Create a comprehensive fix plan for the following vulnerability:\nVulnerability ID: {vulnerability_id}\nDescription: {description}\nPlease include steps for remediation, potential mitigations, and any necessary updates or patches."
    
    openai.api_key = OPENAI_API_KEY
    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[ 
            {"role": "system", "content": "You are an assistant that provides detailed remediation plans for software vulnerabilities."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=500  # Increased token limit for detailed response
    )
    return response.choices[0].message['content'].strip()

# RAG system function
def rag_sbom_response(vulnerability_id, description):
    # Generate context for LLM prompt
    context = generate_context(vulnerability_id, description)
    
    # In this simplified version, we assume there's no relevant data from a database
    print("querying LLM to create a fix plan...")
    response = generate_fix_plan(vulnerability_id, description)
    return response

# Main function to execute the RAG system with user input
def main(vulnerability_id, description):
    try:
        # Execute RAG system
        response = rag_sbom_response(vulnerability_id, description)
        print("Response:")
        return response
    except Exception as e:
        print(f"An error occurred: {e}")
