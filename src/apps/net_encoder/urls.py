from django.urls import path
from .views import ReadCardView, WriteCardView, ResetCardView, ReadCardUIDView

urlpatterns = [
    path("card/uid", ReadCardUIDView, name="read_card_uid"),        
    path("card/cardupsm", WriteCardView, name="write_card_data"),   
    path("card/data", ReadCardView, name="read_card_data"),          
    path("card/reset", ResetCardView, name="reset_card"),
]
