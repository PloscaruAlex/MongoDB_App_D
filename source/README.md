    Ploscaru Alexandru - 321CD

    Pentru implementarea etapei 2 a proiectului m-am folosit de functiile 
create in prima etapa a proiectului, cele oferite de schelet. In cadrul 
fiecarei functii din 'api', am utilizat functia respectiva, creata anterior, 
pentru a manipula baza de date.

    Pentru returnarea unor mesaje de tip Json am folosit libraria 
'vibe.d'. In majoritatea functiilor pur si simplu am creat un json cu 
'serializeToJson' cu un mesaj sugestiv, dar cel mai important a fost in 
cadrul functiei 'authUser', unde am fost nevoit sa creez un obiect de tip 
Json si sa adaug campul 'AccessToken' manual, si sa generez un token de 
autentificare.

    Pentru fiecare eroare am verificat valoarea returnata de functiile 
care lucreaza cu baza de date si in functie de acestea, am dat 'throw' 
la o noua exceptie pentru a schimba statusul HTTP.