import os
import json
import chromadb
import requests
from bs4 import BeautifulSoup
from pdfminer.high_level import extract_text
from sentence_transformers import SentenceTransformer
import textwrap

client = chromadb.PersistentClient(path="p4_vector_db")
collection = client.get_or_create_collection("p4_documents")

embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

def get_embedding(text):
    """Generates an embedding for the given text."""
    return embedding_model.encode(text).tolist()

def chunk_text(text, chunk_size=512, min_chunk_size=100):
    """Splits text into smaller chunks for better retrieval, ensuring meaningful chunks."""
    chunks = textwrap.wrap(text, width=chunk_size)
    return [chunk for chunk in chunks if len(chunk) > min_chunk_size]

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

def add_pdf_to_database(pdf_path):
    """Extracts text from a PDF, chunks it, and stores only new chunks in ChromaDB."""
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"PDF not found: {pdf_path}")
    
    text = extract_text(pdf_path)
    chunks = chunk_text(text)
    base_filename = os.path.basename(pdf_path)
    existing_ids = set(collection.get()["ids"])
    
    new_chunks = []
    for i, chunk in enumerate(chunks):
        chunk_id = f"{base_filename}-{i}"
        if chunk_id not in existing_ids:
            new_chunks.append((chunk_id, chunk))
    
    if not new_chunks:
        print(f"All chunks from {base_filename} are already in the database. Skipping addition.")
        return
    
    # Add only the new chunks
    for chunk_id, chunk in new_chunks:
        collection.add(
            ids=[chunk_id],
            documents=[chunk],
            embeddings=[get_embedding(chunk)],
            metadatas=[{"filename": base_filename, "chunk": chunk_id, "file_path": pdf_path}]
        )
    
    print(f"Added {len(new_chunks)} new chunks from {base_filename} to ChromaDB!")

def build_database():
    """Ensures that ChromaDB only adds new PDFs and does not skip processing if new files exist."""
    existing_files = {meta["filename"] for meta in collection.get()["metadatas"]} if collection.count() > 0 else set()
    
    pdf_files = [f for f in os.listdir() if f.endswith(".pdf")]
    
    new_files = [f for f in pdf_files if f not in existing_files]
    if not new_files:
        print("No new PDF files found. Skipping addition.")
        return
    
    for pdf_file in new_files:
        add_pdf_to_database(pdf_file)
    
    print("Database update complete.")

if __name__ == "__main__":
    build_database()

__all__ = ["retrieve_documents", "add_pdf_to_database"]

