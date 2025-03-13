import sys
import re
import os
from db_p4 import retrieve_documents
import ollama

def sanitize_filename(query):
    """Convert query text into a safe filename."""
    filename = re.sub(r'[^a-zA-Z0-9_]', '_', query)[:50]  # Replace special chars, limit length
    return f"{filename}.p4"

def generate_response(query, model_name=""):
    """Retrieves relevant documents and generates a response using Ollama with Chain of Thought reasoning."""
    relevant_docs = retrieve_documents(query, top_k=3)

    # Handle incorrect data types
    if any(isinstance(doc, list) for doc in relevant_docs):
        relevant_docs = [item for sublist in relevant_docs for item in sublist]  # Flatten

    # Ensure all elements are strings
    relevant_docs = list(map(str, relevant_docs))

    if relevant_docs:
        context = "\n".join(relevant_docs)
        data_source = "DATABASE MATCH FOUND"
    else:
        context = "No relevant documents found."
        data_source = "GENERATED FROM BEST KNOWLEDGE"

    prompt = f"""You are a specialized AI in the P4 programming language. Use Chain of Thought reasoning to first analyze the problem, break it into steps, and then generate **only valid P4 code** using the best available references.

    --- Context ---
    {context}
    ----------------
    
    **Question:** {query}

    **RULES**:
    1. Decompose the problem step-by-step (Chain of Thought reasoning).
    2. Reference provided context when applicable.
    3. If the context is incomplete, intelligently infer missing parts.
    4. Generate only valid P4 code based on the analysis.
    5. Return only valid P4 code with no explanations or comments.
    
    **Step 1: Problem Breakdown**
    Think through the problem carefully. What are the key components needed for the P4 implementation?
    
    **Step 2: Logical Plan**
    Outline how the program will be structured before writing the code.
    
    **Step 3: Generate the final P4 code**
    
    Provide only the valid P4 code below:
    """

    response = ollama.chat(model=model_name, messages=[{"role": "user", "content": prompt}])

    generated_code = response["message"]["content"]

    # Add source note if no database references were found
    if data_source == "GENERATED FROM BEST KNOWLEDGE":
        generated_code = f"// Note: Generated based on best knowledge.\n{generated_code}"

    # Print to terminal
    print("\nOllama Response:\n", generated_code)

    # Save to .p4 file
    filename = sanitize_filename(query)
    try:
        with open(filename, "w") as f:
            f.write(generated_code)
        print(f"\nP4 code saved to: {filename}")
    except Exception as e:
        print(f"\nFailed to save P4 file: {e}")

    return generated_code

# Test case
query = "Can you generate a P4 program that implements a simple firewall with ACL rules?"
response = generate_response(query)
