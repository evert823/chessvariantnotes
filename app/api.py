from fastapi import APIRouter
from app.models.text_input import TextInput
from app.services.hello_world_service import try_helloworld

router = APIRouter()

@router.post("/tryhelloworld")
def receive_text(input: TextInput):
    return try_helloworld(input)
