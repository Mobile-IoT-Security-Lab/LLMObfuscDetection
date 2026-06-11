from   transformers import AutoTokenizer
from   pydantic     import BaseModel
import urllib.request
import urllib.error
import tiktoken
import ollama
import openai
import json
import os


def isOpenAiModel(model):
    modelName = model.lower()
    return modelName.startswith("gpt-") and not modelName.startswith("gpt-oss")

# Helper function to validate that the provided schema model is a Pydantic BaseModel class and return it. Raises a TypeError if the validation fails.
def _getSchemaClass(schemaModel):
    if isinstance(schemaModel, type) and issubclass(schemaModel, BaseModel):
        return schemaModel
    raise TypeError("schemaModel must be a Pydantic BaseModel class.")

# Parse the raw JSON reply from the LLM and validate it against the provided Pydantic schema model, returning the validated data as a dictionary.
def _parseStructuredReply(rawReply, schemaModel):
    schemaClass     = _getSchemaClass(schemaModel)
    parsedReply     = json.loads(rawReply)
    validatedReply  = schemaClass.model_validate(parsedReply)
    return validatedReply.model_dump()

##### OLLAMA API ######
# Interface for interacting with the Ollama API
class OllamaInterface:
    # Fields
    model           = None
    client          = None
    contextWindow   = None

    # Initialize the OllamaInterface with a specified model
    def __init__(self, model='llama3.1', contextWindow = 128000):  
        # Create an Ollama client using the server address from environment variables
        self.client = ollama.Client(host=os.environ["OLLAMA_SERVER"])

        # Set the model to be used
        self.model          = model
        self.contextWindow  = contextWindow

    # Send a simple request to the Ollama API and return the response message
    def sendRequest(self, prompt):
        response = self.client.chat(
            model       = self.model, 
            messages    = [{'role': 'user', 'content': prompt}]
        )
        # Return the content of the response message
        return response['message']['content']

    # Report whether this backend supports native schema-constrained generation.
    def supportsStructuredOutput(self):
        return True

    # Send a request and enforce a JSON schema on the reply.
    def sendRequestWithSchema(self, prompt, schemaModel):
        schemaClass = _getSchemaClass(schemaModel)
        response = self.client.chat(
            model    = self.model,
            messages = [{'role': 'user', 'content': prompt}],
            format   = schemaClass.model_json_schema()
        )

        rawReply = response['message']['content']
        return {
            "rawReply"    : rawReply,
            "parsedReply" : _parseStructuredReply(rawReply, schemaClass)
        }

    # Create a conversation and send multiple messages
    def createConversation(self):
        return OllamaConversation(self.client, self.model)
    
    # Create a conversation with structured output using a Pydantic schema
    def createConversationWithOutputSchema(self, schemaModel):
        return OllamaConversationWithOutputSchema(self.client, self.model, schemaModel)

# Class to handle a conversation with the Ollama API
class OllamaConversation:
    def __init__(self, client, model):
        self.client     = client
        self.model      = model
        self.messages   = []

    # Send a message and get a reply
    def sendMessage(self, prompt):
        self.messages.append({'role': 'user', 'content': prompt})
        response = self.client.chat(
            model=self.model, messages=self.messages
        )
        reply = response['message']['content']
        self.messages.append({'role': 'assistant', 'content': reply})
        return reply

    # Get the full list of messages in the conversation
    def getMessagesHistory(self):
        return self.messages

    # Get the last available reply from the LLM
    def getLastReply(self):
        for message in reversed(self.messages):
            if message['role'] == 'assistant':
                return message['content']
        return None

# Class to handle a conversation with the Ollama API with structured output using Pydantic schema
class OllamaConversationWithOutputSchema:
    def __init__(self, client, model, schemaModel):
        self.client         = client
        self.model          = model
        self.schemaModel    = _getSchemaClass(schemaModel)
        self.messages       = []


    def sendMessage(self, prompt):
        self.messages.append({'role': 'user', 'content': prompt})

        # Send request with schema enforcement
        response = self.client.chat(
            model       = self.model,
            messages    = self.messages,
            format      = self.schemaModel.model_json_schema()
        )

        # Extract raw reply
        rawReply = response['message']['content']

        # Store raw message for conversation history
        self.messages.append({'role': 'assistant', 'content': rawReply})

        # Return
        return rawReply

    def getMessagesHistory(self):
        return self.messages

    def getLastReply(self):
        for message in reversed(self.messages):
            if message['role'] == 'assistant':
                return message['content']
        return None

# Tokenizer for the Llama model
class OllamaTokenizer:
    def __init__(self, model):
        # Llama family
        if "llama" in model.lower():
            self.tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3.1-8B-Instruct")
        # Gemma family
        elif "gemma" in model.lower():
            self.tokenizer = AutoTokenizer.from_pretrained("google/gemma-7b")
        # Phi family
        elif "phi" in model.lower():
            self.tokenizer = AutoTokenizer.from_pretrained("microsoft/Phi-4-mini-instruct")
        # Use llama just in case
        else:
            self.tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3.1-8B-Instruct")
    
    # Get the number of tokens in a given text
    def getNumTokens(self, text):
        # Tokenize the input text using the tokenizer
        tokens      = self.tokenizer(text)
        numTokens   = len(tokens['input_ids'])
        return numTokens

##### OPENAI API #####
# Interface for interacting with the OpenAI GPT API
class OpenAiInterface:
    # Fields
    openaiApiKey        = None
    model               = None
    pricing             = None
    client              = None
    contextWindow       = None

    # Initialize the OpenAiInterface with a specified model and pricing
    def __init__(self, model, pricing = 0.15, contextWindow = 128000):  
        # Get the OpenAI API key from environment variables
        self.openaiApiKey = os.environ["OPENAI_API_KEY"]

        # Create an OpenAI client using the API key
        self.client = openai.OpenAI(api_key=self.openaiApiKey)

        # Set the model and pricing to be used
        self.model          = model
        self.pricing        = pricing
        self.contextWindow  = contextWindow


    # Estimate the cost for a given string based on the number of tokens
    def getPriceForString(self, prompt):
        numTokens = self.getNumTokensFromString(prompt)
        price = numTokens / 1e6 * self.pricing
        return price

    # Send a request to the OpenAI API and return the response message
    def sendRequest(self, prompt):
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{
                "role": "user",
                "content": prompt,
            }]
        )
        # Return the content of the response message
        return response.choices[0].message.content

    # Report whether this backend supports native schema-constrained generation.
    def supportsStructuredOutput(self):
        return False
    
    # Create a conversation and send multiple messages
    def createConversation(self):
        return OpenAiConversation(self.client, self.model)

# Class to handle a conversation with the OpenAI GPT API
class OpenAiConversation:
    def __init__(self, client, model):
        self.client = client
        self.model = model
        self.messages = []

    # Send a message and get a reply
    def sendMessage(self, prompt):
        self.messages.append({'role': 'user', 'content': prompt})
        response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages
            )
        reply = response.choices[0].message.content
        self.messages.append({'role': 'assistant', 'content': reply})
        return reply

    # Get the full list of messages in the conversation
    def getMessages(self):
        return self.messages

    # Get the last available reply from the LLM
    def getLastReply(self):
        for message in reversed(self.messages):
                if message['role'] == 'assistant':
                    return message['content']
        return None

# Tokenizer for the OpenAi model
class OpenAiTokenizer:
    def __init__(self, encoder="cl100k_base"):
        self.encoder = encoder

    def getNumTokens(self, text):
        numTokens = len(tiktoken.get_encoding(self.encoder).encode(text))
        return numTokens

##### GEMINI API #####
# Interface for interacting with Google Gemini models via REST API
class GeminiInterface:
    # Fields
    geminiApiKey     = None
    model            = None
    contextWindow    = None
    baseUrl          = None

    # Initialize Gemini interface with a specified model
    def __init__(self, model = "gemini-2.0-flash", contextWindow = 128000):
        self.geminiApiKey   = os.environ["GEMINI_API_KEY"]
        self.model          = model
        self.contextWindow  = contextWindow
        self.baseUrl        = "https://generativelanguage.googleapis.com/v1beta"

    # Build endpoint URL for generateContent
    def _buildGenerateContentUrl(self):
        return "{}/models/{}:generateContent?key={}".format(self.baseUrl, self.model, self.geminiApiKey)

    # Parse Gemini REST response and return text
    def _extractResponseText(self, responseData):
        candidates = responseData.get("candidates", [])
        if len(candidates) == 0:
            raise ValueError("Gemini response does not contain candidates.")

        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if len(parts) == 0:
            return ""

        textParts = [part.get("text", "") for part in parts]
        return "".join(textParts)

    # Send content to Gemini and return the raw text response
    def _sendContents(self, contents):
        payload = {
            "contents": contents
        }

        request = urllib.request.Request(
            self._buildGenerateContentUrl(),
            data    = json.dumps(payload).encode("utf-8"),
            headers = {"Content-Type": "application/json"},
            method  = "POST"
        )

        try:
            with urllib.request.urlopen(request) as response:
                responseBody = response.read().decode("utf-8")
                responseData = json.loads(responseBody)
        except urllib.error.HTTPError as exc:
            errorBody = exc.read().decode("utf-8") if exc.fp is not None else ""
            raise RuntimeError("Gemini API HTTP error {}: {}".format(exc.code, errorBody))
        except urllib.error.URLError as exc:
            raise RuntimeError("Gemini API connection error: {}".format(exc.reason))

        return self._extractResponseText(responseData)

    # Send a single-turn request
    def sendRequest(self, prompt):
        contents = [{
            "role": "user",
            "parts": [{"text": prompt}]
        }]
        return self._sendContents(contents)

    # Report whether this backend supports native schema-constrained generation.
    def supportsStructuredOutput(self):
        return False

    # Create a conversation and send multiple messages
    def createConversation(self):
        return GeminiConversation(self)

# Class to handle a conversation with Gemini API
class GeminiConversation:
    def __init__(self, interface):
        self.interface = interface
        self.messages = []

    # Convert internal messages to Gemini REST format
    def _toGeminiContents(self):
        contents = []
        for message in self.messages:
            geminiRole = "user" if message["role"] == "user" else "model"
            contents.append({
                "role"  : geminiRole,
                "parts" : [{"text": message["content"]}]
            })
        return contents

    # Send a message and get a reply
    def sendMessage(self, prompt):
        self.messages.append({"role": "user", "content": prompt})
        reply = self.interface._sendContents(self._toGeminiContents())
        self.messages.append({"role": "assistant", "content": reply})
        return reply

    # Get the full list of messages in the conversation
    def getMessages(self):
        return self.messages

    # Get the last available reply from Gemini
    def getLastReply(self):
        for message in reversed(self.messages):
            if message["role"] == "assistant":
                return message["content"]
        return None
