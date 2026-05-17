from app.classes.helloworld import HelloWorld
from app.models.text_input import TextInput

def try_helloworld(input: TextInput):
    try:
        hw = HelloWorld(input.text)
        return {
            "message": f"{hw.message}",
            "orig_input": f"{input.text}"
        }
    except Exception as e:
        return {"message": f"Error: {e}"}
    
