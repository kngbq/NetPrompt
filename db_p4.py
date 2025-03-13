import os
import json
import chromadb
import requests
from bs4 import BeautifulSoup
from pdfminer.high_level import extract_text
from sentence_transformers import SentenceTransformer
import textwrap

# Initialize ChromaDB client **only once**
client = chromadb.PersistentClient(path="p4_vector_db")
collection = client.get_or_create_collection("p4_documents")

# Load the embedding model once
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

def get_embedding(text):
    """Generates an embedding for the given text."""
    return embedding_model.encode(text).tolist()

def chunk_text(text, chunk_size=512, min_chunk_size=100):
    """Splits text into smaller chunks for better retrieval, ensuring meaningful chunks."""
    chunks = textwrap.wrap(text, width=chunk_size)
    return [chunk for chunk in chunks if len(chunk) > min_chunk_size]

# Function to retrieve documents
def retrieve_documents(query, top_k=3, file_type=None):
    """Retrieves documents based on query similarity with optional filtering."""
    query_embedding = get_embedding(query)
    results = collection.query(query_embeddings=[query_embedding], n_results=top_k)
    
    if file_type:
        results["documents"] = [
            doc for doc, meta in zip(results["documents"], results["metadatas"])
            if meta.get("file_type") == file_type
        ]
    
    return results["documents"] if "documents" in results else []

# Function to add a PDF to the database
def add_pdf_to_database(pdf_url, pdf_filename):
    """Downloads and adds a PDF in chunks to ChromaDB with deduplication."""
    pdf_path = pdf_filename
    
    try:
        response = requests.get(pdf_url, timeout=10)
        response.raise_for_status()
        with open(pdf_path, "wb") as file:
            file.write(response.content)

        text = extract_text(pdf_path)
        chunks = chunk_text(text)
        
        existing_ids = set(collection.get()["ids"])

        for i, chunk in enumerate(chunks):
            chunk_id = f"{pdf_filename}-{i}"
            if chunk_id not in existing_ids:
                collection.add(
                    ids=[chunk_id],
                    documents=[chunk],
                    embeddings=[get_embedding(chunk)],
                    metadatas=[{"filename": pdf_filename, "chunk": i, "repo_url": pdf_url}]
                )
        
        print(f"{pdf_filename} successfully added to ChromaDB in chunks!")
    except requests.RequestException as e:
        print(f"Error downloading {pdf_filename}: {e}")

# Function to add exercises from P4 tutorials
def add_p4_exercises():
    """Fetches and adds P4 exercises in chunks to the database using GitHub API with deduplication."""
    base_api_url = "https://api.github.com/repos/p4lang/tutorials/contents/exercises"
    try:
        response = requests.get(base_api_url, timeout=10)
        response.raise_for_status()
        exercises = response.json()
        
        existing_ids = set(collection.get()["ids"])
        
        for exercise in exercises:
            if exercise["type"] == "dir":
                exercise_name = exercise["name"]
                exercise_url = exercise["html_url"]
                
                # Fetch exercise details
                exercise_content = f"Exercise: {exercise_name} located at {exercise_url}"
                chunks = chunk_text(exercise_content)
                
                for i, chunk in enumerate(chunks):
                    chunk_id = f"{exercise_name}-{i}"
                    if chunk_id not in existing_ids:
                        collection.add(
                            ids=[chunk_id],
                            documents=[chunk],
                            embeddings=[get_embedding(chunk)],
                            metadatas=[{"filename": exercise_name, "file_type": "directory", "chunk": i, "repo_url": exercise_url}]
                        )
                print(f"Added exercise: {exercise_name} in chunks.")
    except requests.RequestException as e:
        print(f"Error fetching exercises: {e}")

# Function to check & add new documents only if needed
def build_database():
    """Ensures that ChromaDB only adds new documents and does not duplicate embeddings."""
    existing_count = collection.count()
    if existing_count > 0:
        print(f"Database already populated with {existing_count} documents. Checking for missing documents...")
    
    # Add P4 Cheat Sheet
    add_pdf_to_database("https://raw.githubusercontent.com/p4lang/tutorials/master/p4-cheat-sheet.pdf", "p4-cheat-sheet.pdf")
    
    # Add P4_16 Tutorial PDF
    add_pdf_to_database("https://opennetworking.org/wp-content/uploads/2020/12/p4_d2_2017_p4_16_tutorial.pdf", "p4-16-tutorial.pdf")
    
    # Add P4 Exercises
    add_p4_exercises()
    
    print("Database update complete.")

# **Only execute database build if running this script directly**
if __name__ == "__main__":
    if collection.count() > 0:
        print(f"Database already exists with {collection.count()} documents. Skipping rebuild.")
    else:
        build_database()

# Ensure functions are importable without triggering database rebuild
__all__ = ["retrieve_documents"]

