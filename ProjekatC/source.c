//Milovan Srejic NRT-11/17
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h> 
#define MAX1 40  //Definisanje konstanti
#define BROJ1 26 
#define BROJ2 10 

typedef enum{GRESKA_DODELE, GRESKA_CITANJA, GRESKA_OTVARANJA, GRESKA_PROMENE}Greska; //Nabrajanje mogucih gresaka
char *poruke[]={ //Niz koji sadrzi poruke o razlicitim greskama
	"\nGreska pri dinamickoj dodeli memorije!\n",
	"\nGreska pri citanju podataka iz datoteke!\n",
	"\nGreska pri otvaranju datoteke!\n",
	"\nGreska pri promeni memorije!\n"
};

struct rezultati { //Struktura rezultati koju koristimo za prikaz TOP 10 najboljih rezultata
	char ime[MAX1+1];
	int bodovi;
};

int glavni_meni(void); //Funkcija koja predstavlja glavni meni. Poziva se iz glavne funkcija(main-a).
int igra(void); //Kljucna funkcija. Ona se poziva iz glavne funkcija(main-a). Iz nje se pozivaju funkcije kreiranje_niza_abecede, rezultati_upis, nastavak_ili_kraj i resetovanje.
int nastavak_ili_kraj(void); //Funkcija koja postavlja pitanje na kraju igre da li se zeli nova igra ili ne. Poziva se iz funkcije igra.
int kreiranje_niza_abecede(char *niz_slova); //Funkcija koja kreira niz od slova abecede. Poziva se iz funkcije igra.
void rezultati_upis(int broj_poena); //Funkcija u kojoj svaki rezultat upisujemo u binarnu datoteku rezultati.bin. Poziva se iz funkcije igra.
void rezultati_prikaz(void); //Funkcija koja prikazuje TOP 10 najboljih rezultata. Poziva se iz glavne funkcija(main-a).
void uputstvo(void); //Funkcija koja predstavlja upustvo o igri. Poziva se iz glavne funkcije(main-a).
void resetovanje(int *brojac, int *broj_poena, int *broj_crtica, int *broj_pokusaja); //Funkcija koja vraca odredjene podatke na podrazumevane vrednosti. Poziva se iz funkcije igra.
void poruka(Greska); //Funkcija koja se koristi za prikaz poruka o greskama. Poziva se u funkciji igra, rezultati_upis i rezultati_prikaz.

main()
{
	int opcija,opcija1,opcija2,odgovor_figra;

	while(1)
	{
		printf("      *** DOBRODOSLI U IGRU VESANJA ***");
		printf("\n_____________________________________________\n");
		opcija = glavni_meni();
		if(opcija == 1) //Zapocinje se igra
		{ 
			system("cls"); //Funkcija koja brise prozor prikaza
			odgovor_figra = igra();
			if(odgovor_figra == 0) //Ako je povratna vrednost funkcije 0 to znaci povratak u glavni meni
				continue;
		}
		else if(opcija == 2) //Otvara se uputstvo o igri
		{
			system("cls"); 
			uputstvo();
			printf("\n1 - povratak u glavni meni\n0 - izlaz iz programa\n"); //Mogucnost izlaska iz igre ili povratak u glavni meni
			do
			{
				printf("\nUnesite opciju: ");
				opcija1 = getchar(); fflush(stdin); //Unos jedne od ponudjenih opcija
				if(opcija1 != '0' && opcija1 != '1')
					printf("\nUNELI STE OPCIJU KOJA NE POSTOJI U PONUDJENIM. POKUSAJTE PONOVO!\n");
			}while(opcija1 != '0' && opcija1 != '1');
			if(opcija1 == '1')
			{
				system("cls");
				continue;
			}
			else if(opcija1 == '0')
			{
				system("cls");
				exit(1);
			}
		}
		else if(opcija == 3) //Otvaranje liste top 10 rezultata
		{
			system("cls");
			rezultati_prikaz();
			printf("\n1 - povratak u glavni meni\n0 - izlaz iz programa\n");
			do
			{
				printf("\nUnesite opciju: ");
				opcija2 = getchar(); fflush(stdin); //Unos jedne od ponudjenih opcija
				if(opcija2 != '0' && opcija2 != '1')
					printf("\nNISTE UNELI DOZVOLJENE OPCIJE!\n");
			}while(opcija2 != '0' && opcija2 != '1');
			if(opcija2 == '1')
			{
				system("cls");
				continue;
			}
			else if(opcija2 =='0')
			{
				system("cls");
				exit(1);
			}
		}
		else if(opcija == 4) //Izlaz iz programa
		{
			system("cls");
			exit(1);
		}
	}
}
int glavni_meni(void) 
{
	int opcija;

	printf("\n 1. Zapocnite igru\n 2. Uputstvo o igri\n 3. Lista TOP 10 rezultata\n 4. Izlaz iz igre\n");
	printf("\n_____________________________________________\n");
	do
	{
		printf("\nUnesite opciju: ");
		scanf("%d",&opcija); //Unos jedne od ponudjenih opcija u glavnom meniju
		fflush(stdin);
		if(opcija != 1 && opcija != 2 && opcija != 3 && opcija != 4)
		{
			printf("\nUNELI STE OPCIJU KOJA NE POSTOJI U PONUDJENIM. POKUSAJTE PONOVO!\n");
		}
	}while(opcija != 1 && opcija != 2 && opcija != 3 && opcija != 4); 

	return opcija;
}
int igra(void) 
{
	int i, j, k, m, brojac_slova, brojac=7, duzina_reci, broj_pokusaja=7, pomocni_brojac=0, broj_poena=0, nastavi_zavrsi,provera=0,broj_crtica=0;
	int opcija,nadjen=0, opcija_oblast;
	char *niz_slova, pom_niz_slova[BROJ1+1], *rec_od_crtica, *nepoznata_rec, slovo, odgovor[MAX1+1], *skroz_nepoznata, oblast[MAX1+1], smajli = 1;
	time_t timer; 
	FILE *fptr1;

	
	srand(time(&timer)); 
	
	while(1) //U ovoj petlji je sve o igri
	{
		if(brojac == 7) //Pomocna promenljiva brojac koja se odnosi na broj iteracija citave petlje
		{
			printf("\nPonudjene oblasti:\n 1. Sport\n 2. Automobili\n 3. Bela tehnika\n 4. Gradovi u Srbiji\n");
			do
			{
				printf("\nUnesite jednu od ponudjenih opcija: ");
				opcija_oblast = getchar(); fflush(stdin); //Unos jedne od ponudjenih opcija za izbor oblasti pitanja
				if(opcija_oblast != '1' && opcija_oblast != '2' && opcija_oblast != '3' && opcija_oblast != '4')
					printf("\nUNELI STE OPCIJU KOJA NE POSTOJI U PONUDJENIM. POKUSAJTE PONOVO!\n");
			}while(opcija_oblast != '1' && opcija_oblast != '2' && opcija_oblast != '3' && opcija_oblast != '4');

			niz_slova = (char *)malloc(BROJ1 + 1);//Dinamicka dodela memorije za kreiranje niza od svih slova abecede
			if(niz_slova == NULL)
				poruka(GRESKA_DODELE);
			brojac_slova = kreiranje_niza_abecede(niz_slova); //Pozivanje funkcije koja kreira niz od slova abecede

			if(opcija_oblast == '1')
			{
				fptr1 = fopen("sport.txt", "r"); //Otvaranje datoteke iz koje se citaju reci
				if(fptr1 == NULL)
					poruka(GRESKA_OTVARANJA);
			}
			else if(opcija_oblast == '2')
			{
				fptr1 = fopen("automobili.txt", "r"); //Otvaranje datoteke iz koje se citaju reci
				if(fptr1 == NULL)
					poruka(GRESKA_OTVARANJA);
			}
			else if(opcija_oblast == '3')
			{
				fptr1 = fopen("bela_tehnika.txt", "r"); //Otvaranje datoteke iz koje se citaju reci
				if(fptr1 == NULL)
					poruka(GRESKA_OTVARANJA);
			}
			else if(opcija_oblast == '4')
			{
				fptr1 = fopen("gradovi.txt", "r"); //Otvaranje datoteke iz koje se citaju reci
				if(fptr1 == NULL)
					poruka(GRESKA_OTVARANJA);
			}
			while (!(k = rand())); //Ovaj deo koda predstavlja citanje iz datoteke pseudorandom reci
			nepoznata_rec = (char *)malloc(MAX1 + 1);
			if(nepoznata_rec == NULL)
				poruka(GRESKA_DODELE);
			m = 0;
			while(m < k)
			{
				if(!fscanf(fptr1,"%s",nepoznata_rec))
					poruka(GRESKA_CITANJA);
				m++;
				if(feof(fptr1))
					rewind(fptr1);
			}
			fclose(fptr1); //Zatvaranje datoteke iz koje se uzima rec
			system("cls");
			printf("\t    ** IGRA POCINJE **");
			printf("\n_____________________________________________\n");
			duzina_reci = strlen(nepoznata_rec);

			for(i=0; i<BROJ1; i++)//Dodeljivanje kreiranog niza od slova abecede pomocnom nizu
			{
				pom_niz_slova[i] = niz_slova[i];
			}
			rec_od_crtica = (char *)malloc(duzina_reci + 1); //Dodeljivanje memorije za niz od donjih crta koje predstavljaju nepoznate karaktere
			if(rec_od_crtica == NULL)
				poruka(GRESKA_DODELE);
			for(i=0; i<duzina_reci; i++) //Kreiranje niza od donjih crta koje predstavljaju nepoznate karaktere
			{
				rec_od_crtica[i] = '_';
			}

			printf("\nPreostali broj pokusaja je:\t%d\n", broj_pokusaja); //Ispis vrednosti na pocetku igre
			printf("Preostali broj poena je:\t%d\n\n", broj_poena);
			for(i=0; i<duzina_reci; i++)
			{
				printf("%c ",rec_od_crtica[i]);
			}
			rec_od_crtica[duzina_reci] = '\0';
			printf("\n\nPonudjena slova za pogadjanje:\n");
			for(i=0; i<BROJ1; i++)
			{
				printf("%c ",niz_slova[i]);
			}
			printf("\n");
		}

		if(broj_crtica > 0) //Postavljanje pitanja korisniku da li zeli da pogadja citavu rec, ako je vec pogodio neko od slova
		{
			do{
				printf("\nDa li zelite da pogodite celu rec(odgovoriti sa Da ili Ne)? ");
				scanf("%s", odgovor); fflush(stdin); //Unos odgovora na postavljeno pitanje da li korisni zeli da pogadja celu rec
				if((strcmp(odgovor, "Da") != 0) && (strcmp(odgovor, "Ne") != 0))
					printf("\nNISTE UNELI ODGOVOR NA TACNO TRAZENI NACIN. POKUSAJTE PONOVO!\n");
			}while((strcmp(odgovor, "Da") != 0) && (strcmp(odgovor, "Ne") != 0));

			if((strcmp(odgovor, "Da") == 0))
			{
				skroz_nepoznata = (char *)malloc(MAX1+1); //Dodela memorije za rec koju pogadja korisnik
				if(skroz_nepoznata == NULL)
					poruka(GRESKA_DODELE);
				printf("Unesite trazenu nepoznatu rec: "); 
				gets(skroz_nepoznata); fflush(stdin); //Pogadjanje celi nepoznate reci
				if(strcmp(skroz_nepoznata,nepoznata_rec)==0)
				{
					printf("\n\nPRONASLI STE TRAZENU REC! CESTITAMO NA POBEDI I OSVOJENOM DODATNOM BROJU POENA!\n\n");
					broj_poena += (broj_pokusaja * 2) + ((duzina_reci-broj_crtica)*10);
					rezultati_upis(broj_poena);
					nastavi_zavrsi = nastavak_ili_kraj(); //Funkcija koja vraca odgovor da li pocinje nova igra ili ne
					if(nastavi_zavrsi == 0)
					{
						system("cls");
						resetovanje(&brojac,&broj_poena,&broj_crtica,&broj_pokusaja); //Resetovanje podataka ako se igra ne nastavlja i povratak u glavni meni

						return 0;
					}
					else
					{
						resetovanje(&brojac,&broj_poena,&broj_crtica,&broj_pokusaja); //Resetovanje podataka pri pocetku nove igre
						system("cls");
						continue;
					}
				}
				else
				{
					printf("\nNISTE POGODILI REC!\n");
				}
			}
		}
		do
		{
			printf("\nUnesite trazeno slovo: "); 
			scanf("%c", &slovo); fflush(stdin); //Unos slova od strane korisnika
			if(!isalpha(slovo))
				printf("\nNISTE UNELI SLOVO!\n");
		}while(!isalpha(slovo));

		for(j=0; j<BROJ1; j++) //Provera da li je uneto slovo vec prethodno unoseno od strane korisnika
		{
			if(toupper(slovo) == pom_niz_slova[j])
			{
				nadjen++;
			}
		}
		for(i=0; i<duzina_reci; i++) //Provera da li trazeno slovo postoji u zadatoj nepoznatoj reci i dodela ili oduzimanje poena
		{
			if(tolower(slovo) == nepoznata_rec[i])
			{
				
				if(nadjen == 0)  //Ako je slovo vec unoseno oduzima se odredjeni broj poena
				{
					provera++;
					if(provera == 1)
					{
						broj_poena -= 2;
						broj_pokusaja--;
						pomocni_brojac++;
					}
				}
				else if(nadjen > 0) //Ako slovo prethodno nije unoseno i postoji u nepoznatoj reci dodaje se 10 poena
				{
					rec_od_crtica[i] = nepoznata_rec[i];
					broj_crtica++;
					provera++;
					if(provera == 1)
					{
						broj_poena += 10;
						pomocni_brojac++;
					}
				}
			}
		}
		provera=0; 

		if(pomocni_brojac == 0) //Ukoliko se slovo ne pronadje u nepoznatoj reci, broj poena i broj pokusaja se smanjuju
		{
			if(nadjen == 0) //Ako je slovo vec unoseno oduzima se odredjeni broj poena
			{
				broj_pokusaja--;
				broj_poena -= 2;
			}
			else if(nadjen > 0) //Ako slovo prethodno nije unoseno i ne postoji u nepoznatoj reci oduzima se 5 poena
			{
				broj_pokusaja--;
				broj_poena -= 5;
			}
		}
		nadjen = 0;
		pomocni_brojac = 0;

		for(i=0; i<BROJ1; i++) //Izbacivanje unetog slova iz pomocnog niza koji sadrzi sva slova abecede
		{
			if(toupper(slovo) == niz_slova[i])
			{
				pom_niz_slova[i] = ' ';
			}
		}

		brojac--;
		if(brojac < 7) //Prikaz stanja o poenima, pokusajima, ponudjenim i pogodjenim slovima 
		{
			printf("\n_____________________________________________\n");
			printf("\nPreostali broj pokusaja je:\t%d\n",broj_pokusaja);
			printf("Preostali broj poena je:\t%d\n\n", broj_poena);
			for(i=0; i<duzina_reci; i++)
			{
				printf("%c ",rec_od_crtica[i]); //Prikaz reci sa crticama posle pogadjanja. Desava se promena ukoliko se pogodi slovo.
			}
			printf("\n\nPonudjena slova za pogadjanje:\n");
			for(i=0; i<BROJ1; i++)
			{
				printf("%c ", pom_niz_slova[i]); //Prikaz ponudjenih slova posle pogadjanja. Desava se promena pri svakom pogadjanju.
			}
			printf("\n");
		}

		if(broj_pokusaja == 0) //Ispitivanje da li je preostali broj pokusaja dosao do nule sto znaci da se igra zavrsava
		{
			printf("\n\nZAO NAM JE. NISTE USPELI DA POGODITE TRAZENU REC!\n\n");
			printf("Trazena rec koju niste pogodili je: %s\n",nepoznata_rec);
			nastavi_zavrsi = nastavak_ili_kraj(); //Funkcija koja vraca odgovor da li pocinje nova igra ili ne
			if(nastavi_zavrsi == 0)
			{
				system("cls");
				resetovanje(&brojac,&broj_poena,&broj_crtica,&broj_pokusaja);

				return 0;
			}
			else if(nastavi_zavrsi == 1)
			{
				resetovanje(&brojac,&broj_poena,&broj_crtica,&broj_pokusaja);
				system("cls");
				continue;
			}
		}
		else if(strcmp(nepoznata_rec,rec_od_crtica) == 0) //Ispitivanje da li je rec pogodjena u celosti sto takodje znaci kraj igre odnosno pobedu korisnika
		{
			printf("\n\nPRONASLI STE TRAZENU REC! CESTITAMO NA POBEDI!\n\n");
			rezultati_upis(broj_poena); //Slanje ostvarenog broja poena funkciji koja to upisuje u datoteku
			nastavi_zavrsi = nastavak_ili_kraj(); //Funkcija koja vraca odgovor da li pocinje nova igra ili ne
			if(nastavi_zavrsi == 0)
			{
				system("cls");
				resetovanje(&brojac,&broj_poena,&broj_crtica,&broj_pokusaja);

				return 0;
			}
			else if(nastavi_zavrsi == 1)
			{
				resetovanje(&brojac,&broj_poena,&broj_crtica,&broj_pokusaja);
				system("cls");
				continue;

			}
		}
	}
	free(niz_slova);
	free(rec_od_crtica);
	free(nepoznata_rec);
	free(skroz_nepoznata); //Oslobadjanje memorije za nizove karaktera
}
int nastavak_ili_kraj(void) 
{
	char nastavak[MAX1+1];

	do
	{
		printf("\nDa li zelite novu igru(odgovoriti sa Da ili Ne)? ");
		gets(nastavak); fflush(stdin); //Unos odgovara Da ili Ne. Odnosi se na pocetak nove igre ili povratak u glavni meni.
		if((strcmp(nastavak,"Da") != 0) && (strcmp(nastavak,"Ne") != 0))
			printf("\nNISTE UNELI ODGOVOR NA TACNO TRAZENI NACIN. POKUSAJTE PONOVO!\n");
	}while((strcmp(nastavak,"Da") != 0) && (strcmp(nastavak,"Ne") != 0));

	if(strcmp(nastavak,"Da") == 0)
	{
		return 1;
	}
	else if(strcmp(nastavak,"Ne") == 0)
	{
		return 0;
	}
}
int kreiranje_niza_abecede(char *niz_slova)
{
	int brojac_slova=0,i;

	for(i='A'; i<='Z'; i++) //Kreiranje niza od svih slova abecede
	{
		*(niz_slova + brojac_slova) = i;
		brojac_slova++;
	}

	return brojac_slova; //Vraca broj slova iz kreiranog niza
}
void rezultati_upis(int broj_poena)
{
	char *ime;
	int i;
	FILE *fptr2;
	struct rezultati pomocni;

	ime = (char *)malloc(MAX1 + 1); //Dodela memorije za promenljivu ime
	if(ime == NULL)
		poruka(GRESKA_DODELE);
	do
	{
		printf("\nUnesite Vase ime(nadimak) koje upisujemo u rezultate: ");
		gets(ime); fflush(stdin);
		if(strlen(ime) > 12)
			printf("\nUNELI STE IME KOJE JE PREDUGACKO. POKUSAJTE PONOVO!\n");
	}while(strlen(ime) > 12); //Ako korisnik unese ime(nadimak) koji ima vise od 12 karaktera vraca ga na ponovni unos
	printf("Vas ostvareni broj poena je: %d\n",broj_poena);
	strcpy(pomocni.ime,ime);
	pomocni.bodovi = broj_poena;
	
	fptr2 = fopen("rezultati.bin", "ab"); //Otvaranje datoteke rezultati.bin za upis u produzetku
	if(fptr2 == NULL)
		poruka(GRESKA_OTVARANJA);
	fwrite(&pomocni, sizeof(struct rezultati), 1, fptr2); //Upis podataka u datoteku rezultati.bin u produzetku sadrzaja. Upisuju se samo rezultati korisnika koji su pogodili rec.

	fclose(fptr2);
	free(ime);
}
void rezultati_prikaz(void)
{
	FILE *fptr2;
	struct rezultati pomocni,*spisak,pom;
	int brojac=0,i,j;

	fptr2 = fopen("rezultati.bin", "rb"); //Otvaranje datoteke rezultati.bin za citanje podataka
	if(fptr2 == NULL)
		poruka(GRESKA_OTVARANJA);
	while(fread(&pomocni,sizeof(struct rezultati),1,fptr2) != NULL) //Citanje svih struktura iz datoteke
	{
		if(brojac == 0)
		{
			spisak = (struct rezultati *)malloc(sizeof(struct rezultati)); //Dinamicka dodela memorije za niz struktura u koju se citaju podaci iz datoteke
			if(spisak == NULL)
				poruka(GRESKA_DODELE);
		}
		else
		{
			spisak = (struct rezultati *)realloc(spisak,(brojac+1)*sizeof(struct rezultati)); //Promena memorije pri svakom citanju novog podatka
			if(spisak == NULL)
				poruka(GRESKA_PROMENE);
		}
		spisak[brojac] = pomocni;
		brojac++;
	}
	fclose(fptr2);

	for(i=0;i<brojac-1;i++) //Sortiranje korisnika po broju bodova od najveceg ka manjem
		for(j=i+1;j<brojac;j++)
			if(spisak[i].bodovi < spisak[j].bodovi)
			{
				pom = spisak[i];
				spisak[i] = spisak[j];
				spisak[j] = pom;
			}
	printf("\t\t** TOP 10 REZULTATA **");
	printf("\n___________________________________________________________\n\n");
	if(brojac == 0) //Uslov ako je prazna datoteka
	{
		printf("DATOTEKA JE PRAZNA!\n");
	}
	else if(brojac < 10) //Uslov ako je u datoteci manje od 10 korisnika
	{
		for(i=0; i<brojac; i++) //Prikaz 10 najboljih rezultata koji su pogodili rec
		{
			if(strlen(spisak[i].ime) > 8)
			{
				printf("%d. Ime igraca: %s\t\tBroj bodova: %d\n\n",i+1,spisak[i].ime,spisak[i].bodovi);
			}
			else
				printf("%d. Ime igraca: %s\t\t\tBroj bodova: %d\n\n",i+1,spisak[i].ime,spisak[i].bodovi);
		} 
	}
	else
	{
		for(i=0; i<BROJ2; i++) //Prikaz 10 najboljih rezultata koji su pogodili rec
		{
			if(strlen(spisak[i].ime) > 8) //Ako je neko ime(nadimak) duze od 8 karaktera ima drugaciji format
			{
				printf("%d. Ime igraca: %s\t\tBroj bodova: %d\n\n",i+1,spisak[i].ime,spisak[i].bodovi);
			}
			else
				printf("%d. Ime igraca: %s\t\t\tBroj bodova: %d\n\n",i+1,spisak[i].ime,spisak[i].bodovi);
		}
	}
	printf("___________________________________________________________\n\n");

	free(spisak); //Oslobadjanje memorije za niz struktura
}
void uputstvo(void) //Uputstvo o igranju
{
	FILE *fptr1;
	int c;

	fptr1 = fopen("uputstvo.txt","r"); //Otvaranje datoteke za citanje. U datoteci se nalazi uputstvo o igri
	if(fptr1 == NULL)
	{
		poruka(GRESKA_OTVARANJA);
	}
	while((c=fgetc(fptr1)) != EOF) //Citanje karakter po karakter
	{
		printf("%c",c);
	}

	fclose(fptr1); //Zatvaranje datoteke uputstvo
}
void resetovanje(int *brojac, int *broj_poena, int *broj_crtica, int *broj_pokusaja) //Resetovanje odredjenih elemenata prilikom pocetka nove igre ili izlaska iz igre
{
	*brojac = 7;
	*broj_poena = 0;
	*broj_crtica = 0;
	*broj_pokusaja = 7;
}
void poruka(Greska status) //Poruke o raznim greskama(dinamicka dodela memorije, otvaranje datoteke za upis ili citanje i promenu memorije)
{
	fprintf(stderr,poruke[status]);
	exit(1);
}