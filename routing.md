# 1 Namjena Rails Router-a

Rails router prepoznaje URL adrese i otprema ih do neke akcije kontrolera. Može i da generiše putanje i URL adrese, izbjegavajući time pisanje stringova u view fajlovima.

## 1.1 Povezivanje URL-a sa kodom

Kada Rails aplikacija primi zahtjev za:

<pre><code>GET /patients/17</code></pre>

pita rutera da isto spoji sa nekom kontroler akcijom. Ako je prva spojena ruta (*engl.* matching route):

<pre><code>get '/patients/:id', to: 'patients#show'</code></pre>

zahtjev se šalje kontroler show akciji patient-a sa { id: '17' } u parametrima.

## 1.2. Generisanje putanja i URL adresa iz koda

Ako izmijenimo prethodnu rutu da bude:

<pre><code>get '/patients/:id' to: 'patients#show', as: 'patient'</code></pre>

a aplikacija u kontroleru sadrži sljedeći kod:

<pre><code>@patient = Patient.find(17)</code></pre>

i ovo je odgovarajući view kod:

<pre><code><%= link_to 'Patient Record', patient_path(@patient) %></code></pre>

ruter će generisati putanju <code>/patients/17</code>.

Ovo će dovesti do znatno preglednijeg koda.

# 2 Resurs rutiranje: Rails Default

Resurs rutiranje (*engl.* resource routing) omogućava brzo deklarisanje svih ruta za dati kontroler. Umjesto posebnog deklarisanja ruta za <code>index</code>, <code>show</code>, <code>new</code>, <code>edit</code>, <code>create</code>, <code>update</code> i <code>destroy</code> akcije, *resourceful* ruta ih deklariše u jednoj liniji koda.

## 2 Resursi na mreži

Browser-i zahtijevaju strane od Railsa praveći zahtjev za URL koristeći određeni HTTP metod, kao <code>GET</code>, <code>POST</code>, <code>PATCH</code>, <code>PUT</code> i <code>DELETE</code>. Svaki metod je zahtjev za izvođenje operacije na resursu. Resurs ruta mapira broj određenih zajteva sa akcijama u jednom kontroleru.

Kada Rails aplikacija primi zahtjeva za:

<pre><code>DELETE /photos/17</code></pre>

pita rutera da isto spoji sa nekom kontroler akcijom. Ako je prva spojena ruta:

<pre><code>resources :photos</code></pre>

Rails bi poslao ovaj zahtjev destroy metodi photos kontroleru sa { id: '17' } u parametrima.

## 2.2 CRUD, glagoli i akcije

U Railsu, *resourceful* ruta obezbjeđuje spajanje između HTTP glagola i URL adresa za kontroler akcije. Po konvenciji, svaka akcija takođe mapira određenu CRUD operaciju u bazi. 

Sljedeći unos u fajlu za rutiranje:

<pre><code>resources :photos</code></pre>

kreira sedam različitih ruta u aplikaciji. Sve su povezane sa Photos kontrolerom:


|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Primjena**|
|GET|/photos|index|prikazuje sve slike|
|GET|/photos/new|new|vraća HTML formu za kreiranje nove slike|
|POST|/photos|create|kreira novu sliku|
|GET|/photos/:id|show|prikazuje određenu sliku|
|GET|/photos/:id/edit|edit|vraća HTML formu za izmjenu slike|
|PATCH/PUT|/photos/:id|update|update-uje određenu sliku|
|DELETE|/photos/:id|destroy|briše određenu sliku|

## 2.3 Putanje i URL helperi

Kreiranje *resourceful* rute će takođe izložiti određen broj helpera kontrolerima u aplikaciji. U slučaju <code>resouces :photos</code>:

* photos_path će vratiti /photos
* new_photo_path će vratiti /photos/new
* edit_photo_path(:id) će vratiti /photos/:id/edit
* photo_path(:id) će vratiti /photos/:id

Svaki od ovih helpera ima i odgovarajući <code>_url</code> helper (kao <code>photos_url</code>) koji vraća istu putanju sa prefiksom trenutnog hosta, porta, kao i prefiksom putanje.

## 2.4 Definisanje više resursa odjednom

<pre><code>resources :photos, :books, :vides</code></pre>

Identično je sa:

<pre><code>resources :photos
resources :books
resources :videos</code></pre>

## 2.5 Pojedinačni resursi

Često imamo resurs koji pretražujemo bez navođenja ID-ja. Npr. u slučaju da želimo da <code>/profile</code> uvijek prikazuje trenutno logovanog korisnika. U ovom slučaju može se koristiti pojedinačni resurs da se spoji <code>/profile</code> (umjesto <code>/profile/:id</code>) sa show akcijom:

<pre><code>get 'profile', to: 'users#show'</code></pre>

Ako predajemo string <code>to</code> će očekivati controller#action format, dok će simbol očekivati akciju:

<pre><code>get 'profile', to: :show</code></pre>

Ova resourceful ruta: 

<pre><code>resource :geocoder</code></pre>

će kreirati šest različitih ruta u aplikaciji. Sve su povezane sa Geocoder kontrolerom:


|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Primjena**|
|GET|/geocoder/new|new|vraća HTML formu za kreiranje geokodera|
|POST|/geocoder|create|kreira novi geokoder|
|GET|/geocoder/:id|show|prikazuje taj jedan jedini geokoder resurs|
|GET|/geocoder/:id/edit|edit|vraća HTML formu za izmjenu geokodera|
|PATCH/PUT|/geocoder/:id|update|update-uje taj jedan određeni geokoder resurs|
|DELETE|/geocoder/:id|destroy|briše geokoder resurs|

Helperi:

* new_geocoder_path će vratiti /geocoder/new
* edit_geocoder_path će vratiti /geocoder/edit
* geocoder_path će vratiti /geocoder

## 2.6 Kontroler namespace-ovi i rutiranje

Namespace-ove najčešće koristimo kada želimo da napravimo grupu kontrolera kao npr. administrativne kontrolere pod Admin:: namespace. Ovi kontroleri bi se nalazili u app/controller/admin direktorijumu, a mogu se grupisati u ruteru:

<pre><code>namespace :admin do
    resource :posts, :comments
end</code></pre>

Ovo će kreirati određen broj ruta za svaki post i comment kontroler. Za Admin::PostsController, Rails će kreirati:

|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Primjena**|
|GET|/admin/posts|index|admin_posts_path|
|GET|/admin/posts/new|new|new_admin_post_path|
|POST|/admin/posts|create|admin_post_path|
|GET|/admin/posts/:id|show|admin_post_path(:id)|
|GET|/admin/posts/:id/edit|edit|edit_admin_post_path(:id)|
|PATCH/PUT|/admin/posts/:id|update|admin_post_path(:id)|
|DELETE|/admin/posts/:id|destroy|admin_post_path(:id)|

Ako želimo da rutiramo /posts (bez prefiksa /admin), za Admin::PostsController koristimo:

<pre><code>scope module: 'admin' do
    resources :posts, :comments
end</code></pre>

ili, za jedan slučaj:

<pre><code>resource :posts, module: 'admin'</code></pre>

Ako želimo da rutiramo /admin/posts za PostsController (bez Admin:: module prefiksa), korstimo:


<pre><code>scope '/admin' do
    resources :posts, :comments
end</code></pre>

ili, za jedan slučaj:

<pre><code>resource :posts, '/admin/posts'</code></pre>

U oba slučaja, imenovane rute ostaju iste kao i kada nismo koristili scope.

|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Helper**|
|GET|/admin/posts|index|posts_path|
|GET|/admin/posts/new|new|new_post_path|
|POST|/admin/posts|create|post_path|
|GET|/admin/posts/:id|show|post_path(:id)|
|GET|/admin/posts/:id/edit|edit|edit_post_path(:id)|
|PATCH/PUT|/admin/posts/:id|update|post_path(:id)|
|DELETE|/admin/posts/:id|destroy|post_path(:id)|

## 2.7 Ugnježdeni resursi

Čest je slučaj korišćenja resursa koji su logički 'children' drugih resursa.

<pre><code>class Magazine < ActiveRecord::Base
  has_many :ads
end
 
class Ad < ActiveRecord::Base
  belongs_to :magazine
end</code></pre>

Ugnježdene (*engl.* nested) rute omogućavaju preslikavanje ovih veza u rutiranju. U ovom slučaju, koristili bismo:

<pre><code>resources :magazines do
    resouces :ads
end</code></pre>

U dodatku rutama za magazine, ova deklaracija će takođe rutirati reklame (ads) na AdsController. URL adrese reklame u zahtjevima za magazin:

|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Primjena**|
|GET|/magazines/:magazine_id/ads|index|lista spisak svih reklama za određeni magazin|
|GET|/magazines/:magazine_id/ads/new|new|vraća HTML formu za kreiranje nove reklama koja pripada određenom magazinu|
|POST|/magazines/:magazine_id/ads|create|kreiranje nove reklame koja pripada određenom magazinu|
|GET|/magazines/:magazine_id/ads/:id|show|prikaz određene reklame koja pripada određenom magazinu|
|GET|/magazines/:magazine_id/ads/:id/edit|edit|vraća HTML formu za izmjenu reklama koja pripada određenom magazinu|
|PATCH/PUT|/magazines/:magazine_id/ads/:id|update|update-ovanje određene reklame koja pripada određenom magazinu|
|DELETE|/magazines/:magazine_id/ads/:id|destroy|brisanje reklame koja pripada određenom magazinu|

Ovo će takođe kreirati routing helpere kao magazine_ads_url i edit_magazine_ad_path. Ovi helperi uzimaju instancu od Magazine kao prvi parametar (magazine_ads_url(@magazine)).

### 2.7.1 Ograničenja na Nesting

Možemo praviti ugnježdene resurse unutar drugih ugnježdenih resursa. Na primjer:

<pre><code>resources :publishers do
  resources :magazines do
    resources :photos
  end
end</code></pre>

U ovom slučaju aplikacija bi prepoznala putanju: <code>/publisher/1/magazines/2/photos/3</code>

Odgovarajući route helper bi bio publisher_magazine_photo_url, zahtijevajući određivanje objekata na sva tri nivoa. Ovo se ne preporučuje. Jamis Buck u svom popularnom [članku](http://weblog.jamisbuck.org/2007/2/5/nesting-resources) kaže:

> Resources should never be nested more than 1 level deep.

### 2.7.2 Shallow Nesting

Jedan od načina za izbjegavanje deep nestinga je generisanje akcija kolekcija pod roditeljskim opsegom. Tako će se razumjeti hijerarhija ali se neće ugnježdavati akcije članova. Dakle, kreiramo rute sa minimalnom količinom informacija, da bi se jedinstveno odredio resurs, kao:

<pre><code>resources :posts do
  resources :comments, only: [:index, :new, :create]
end
resources :comments, only: [:show, :edit, :update, :destroy]</code></pre>

Ova ideja pravi balans između deskriptivnih ruta i deep nestinga. Za ovo postoji i skraćena sintaksa. Koristeći <code>:shallow</code> opciju, prethodni kod možemo zapisati kao:

<pre><code>resources :posts do
  resources :comments, shallow: true
end</code></pre>

Ovu opciju možemo definisati i u roditeljskom resursu:

<pre><code>resources :posts, shallow: true do
  resources :comments
  resources :quotes
  resources :drafts
end</code></pre>

<code>shallow</code> metod DSL-a kreira scope unutar koga je svako ugnježdavanje shallow. Sljedeće će da generiše iste rute kao prethodni primjer:

<code>shallow do
  resources :posts do
    resources :comments
    resources :quotes
    resources :drafts
  end
end</code>

Postoje dvije opcije za scope da izmijeni shallow rute. :shallow:path stavlja prefikse putanjama članova (member paths) sa određenim parametrom:

<pre><code>scope shallow_path: "sekret" do
  resources :posts do
    resources :comments, shallow: true
  end
end</code></pre>

Sljedeće rute će biti generisane:

|  |  | |
| -----------------------| -------------------| --------------- |
|**HTTP glagol**|**Putanja**|**Helper**|
|GET|/posts/:post_id/comments(.:format)|post_comments|
|POST|/posts/:post_id/comments(.:format)|post_comments|
|GET|/posts/:post_id/comments/new(.:format)|new_post_comment|
|GET|/sekret/comments/:id(.:format)|edit_comment|
|GET|/sekret/comments/:id/edit(.:format)|comment|
|PATCH/PUT|/sekret/comments/:id(.:format)|comment|
|DELETE|/sekret/comments/:id(.:format)|comment|

Opcija :shallow_prefix će dodati određeni parametar imenima helpera:

<pre><code>scope shallow_prefix: "sekret" do
  resources :posts do
    resources :comments, shallow: true
  end
end</code></pre>

|  |  | |
| -----------------------| -------------------| --------------- |
|**HTTP glagol**|**Putanja**|**Helper**|
|GET|/posts/:post_id/comments(.:format)|post_comments|
|POST|/posts/:post_id/comments(.:format)|post_comments|
|GET|/posts/:post_id/comments/new(.:format)|new_post_comment|
|GET|/comments/:id(.:format)|edit_secret_comment|
|GET|/comments/:id/edit(.:format)|secret_comment|
|PATCH/PUT|/comments/:id(.:format)|secret_comment|
|DELETE|/comments/:id(.:format)|secret_comment|

## 2.8 Routing concern-i

Routing concerni omogućavaju deklarisanji često korišćenih ruta koje se mogu ponovo koristiti unutar drugih resursa ili ruta.

**Definisanje concerna**

<pre><code>concern :commentable do
  resources :comments
end
 
concern :image_attachable do
  resources :images, only: :index
end</code></pre>

Mogu se koristiti u resursima da se izbjegne duplikacija koda: 

<pre><code>resources :messages, concerns: :commentable
resources :posts, concerns: [:commentable, :image_attachable]</code></pre>

Napisano je ekvivalentno sa:

<pre><code>resources :messages do
  resources :comments
end
 
resources :posts do
  resources :comments
  resources :images, only: :index
end</code></pre>

Takođe se mogu koristiti na bilo kom mjestu u kodu:

<pre><code>namespace :posts do
  concerns :commentable
end</code></pre>

## 2.9 Kreiranje putanja i URL adresa iz objekata

Pored helpera, Rails može da kreira putanje i URL adrese iz niza parametara. Ako imam sljedeći skup ruta:

<pre><code>resources :magazines do
  resources :ads
end</code></pre>

Kada koristimo magazine_ad_path može predati instancu od Magazine i Ad umjesto numeričkog ID-ja:

<pre><code><%= link_to 'Ad details', magazine_ad_path(@magazine, @ad) %></code></pre>

Možemo koristiti url_for sa skupom objekata i Rails će automatski odrediti koju rutu želite:

<pre><code><%= link_to 'Ad details', url_for([@magazine, @ad]) %></code></pre>

U ovom slučaju Rails će vidjeti da je @magazines Magazine i @ad Ad i zbog toga koristiti magazine_ad_path helper. U helperima kao link_to, možemo samo navesti objekat umjesto poziva url_for:

<pre><code><%= link_to 'Ad details', [@magazine, @ad] %></code></pre>

Za druge akcije, potrebno je dodati ime akcije kao prvi element niza:

<pre><code><%= link_to 'Edit Ad', [:edit, @magazine, @ad] %></code></pre>

Ovo omogućava tretiranje instaci modela kao URL adresa i ključna je prednost korićenja ovakvog stila.

## 2.10 Dodavanja više RESTful akcija

Sedam ruta koje RESTful rutiranje kreira kao podrazumijevane, nisu ograničenje. Moguće je dodati dodatne rute koje se primjenjuju na kolekciju ili individualne članove kolekcije.

### 2.10.1 Dodavanje memeber ruta

Member rute se dodaju unutar member bloka unutar resource bloka:

<pre><code>resources :photos do
  member do
    get 'preview'
  end
end</code></pre>

Ovo će prepoznati /photos/1/preview sa GET i rutirati na *preview* akciju PhotosController-a sa resource vrijednošću id-ja iz params[:id]. Kreiraće i preview_photo_url i preview_photo_path helpere.

Unutar bloka member ruta, svako ime rute određuje HTTP glagol koji će da prepozna. Može se koristiti get, patch, post ili delete. Ako nema više member ruta, može se koristiti :on opcija, bez bloka:

<pre><code>resources :photos do
  get 'preview', on: :member
end</code></pre>

:on opcija se može i izostaviti i ovo će kreirati istu member rutu, osim što će vrijednost resource id-ja biti dostupna u params[:photo_id] umjesto params[:id].

### 2.10.2 Dodavanje collection ruta

<pre><code>resources :photos do
  collection do
    get 'search'
  end
end</code></pre>

Ovo će omogućiti Railsu da prepozna putanje poput /photos/search sa GET i rutirati na search akciju PhotosController-a. Kreiraće i search_photos_url i search_photos_path route helpere.

I ovdje je moguće koristiti :on opciju.

**Napomena:**
Da dodamo alternativnu new akciju:
<pre><code>resources :comments do
  get 'preview', on: :new
end</pre></code>

Prepoznaje putanje kao /comments/new/preview sa GET.

# 3 Non-Resourceful rute

Pored resource rutiranja, Rails nudi odličnu podršku za rutiranje proizvoljnih URL adresa na akcije. Ovdje se svaka ruta u aplikaciji posebno podešava.

Iako se preporučuje resourceful rutiranje, postoji mnogo mjesta gdje je prikladnije koristiti obično rutiranje.

## 3.1 Bound (granični) parametri

Kada se obična putanja podešava, predaje se niz simbola koje Rails mapira na djelova dolaznog HTTP zahtjeva. Dva od ovih simbola su posebna: <code>:controller</code> mapira ime kontrolera u aplikaciji i <code>:action</code> mapira ime akcije unutar kontrolera. Na primjer:

<pre><code>get ':controller(/:action(/:id))'</code></pre>

Ako je dolazni zahtjev /photos/show/1 procesiran od ove rute, onda će se show akcija dodati u PhotosController a parametar '1' će biti dostupan kao params[:id]. Ova ruta će takođe rutirati dolazni zahtjev /photos na PhotosController#index, jer su :action i :id opcioni parametri.

## 3.2 Dinamički segmenti

Broj dinamičkih segmenata unutar obične rute nije ograničen. Sve osim :controller i :action će biti dostupno akciji kao dio parametara.

<pre><code>get ':controller/:action/:id/:user_id'</code></pre>

Dolazna putanja /photos/show/1/2 će biti otpremljena show akciji PhotosController-a. Params[:id] će biti '1' i params[:user_id] će biti '2'.

**Napomena:** :namespace-ovi i :module-i se ne mogu koristiti sa :controller segmentom putanje. Ako je ipak neophodno, onda se namespace može navesti pomoću ograničenja: <code>get ':controller(/:action(/:id))', controller: /admin\/[^\/]+/</code>

## 3.3 Statički segmenti

<pre><code>get ':controller/:action/:id/with_user/:user_id'</code></pre>

Ova ruta će odgovarati na putanje kao /photos/show/1/with_user/2.

## 3.4 String upit

Params će prihvatiti i bilo koji parametar iz stringa upita. Na primjer, za ovu rutu:

<pre><code>get ':controller/:action/:id'</code></pre>

dolazna putanja /photos/show/1?user_id=2 će biti otpremljena na show akciju Photos kontrolera. params će biti { controller: 'photos', action: 'show', id: '1', user_id: '2' }.

## Definisanje default-a

Unutuar rute, nije potrebno čak ni koristiti :controller i :action simbole. Mogu se predati po defaultu:

<pre><code>get 'photos/:id', to: 'photos#show'</code></pre>

Sa ovom rutom, Rails će spojiti dolaznu putanju /photos/12 sa show akcijom PhotosController.

I drugi defaulti se mogu definisati u ruti u vidu hasha za :default opciju. Ovo se odnosi i na parametri koji nisu određeni kao dinamički segmenti. Na primjer:

<pre><code>get 'photos/:id', to: 'photos#show', defaults: { format: 'jpg' }</code></pre>

Rails bi photos/12 poslao show akciji PhotosController-a i postavio params[:format] na 'jpg'.

## 3.6 Imenovanje ruta

Imenovanje ruta se vrši :as opcijom:

<pre><code>get 'exit', to: 'sessions#destroy', as: :logout</code></pre>

Ovo će kreirati logout_path i logout_url kao helpere aplikacije. Pozivanje logout_path će vratiti /exit.

Ovo se može koristi i za preklapanje metoda rutiranja definisanih od resursa, kao:

<pre><code>get ':username', to: 'users#show', as: :user</code></pre>

Ovo će definisati user_path metodu koja će biti dostupna u kontrolerima, helerima i view fajlovima koje će ići na rutu poput /bob.

## 3.7 Ograničenje HTTP glagola

Metode get, post, put i delete se koriste za ograničavanje ruta na određen glagol. Može se koristiti match metod sa :via opcijom da se navede više glagola odjednom:

<pre><code>match 'photos', to: 'photos#show', via: [:get, :post]</code></pre>

Ili sve odjednom:

<pre><code>match 'photos', to: 'photos#show', via: :all</code></pre>

## 3.8 Ograničenja segmenata

Opciju :constraints koristimo da odredimo format za dinački segment:

<pre><code>get 'photos/:id', to: 'photos#show', constraints: { id: /[A-Z]\d{5}/ }</code></pre>

Rails će spojiti putanju kao /photos/A01234 ali ne i /photos/56789

Istu rutu je moguće još bolje napisati kao: <pre><code>get 'photos/:id', to: 'photos#show', id: /[A-Z]\d{5}/</code></pre>

:constraints uzima regularni uz napomenu da se [anchor simboli](http://msdn.microsoft.com/en-us/library/h5181w5w(v=vs.110).aspx) ne mogu koristiti.

Ali oni nisu ni potrebni.

## 3.9 Ograničenja zasnovana na request objektima

Moguće je ograničiti i rutu zasnovanu na bilo kojoj metodi na **Request objektu** (pogledati: *10.1 - Action Controller Overview*) koja vraća String.

Request-based ograničenje se određuje isto kao i ono na segmentu:

<pre><code>get 'photos', constraints: {subdomain: 'admin'}</code></pre>

Ograničenja je moguće odrediti unutar bloka:

<pre><code>namespace :admin do
  constraints subdomain: 'admin' do
    resources :photos
  end
end</code></pre>

## 3.11 Route Globbing i Wildcard segmenti

**Route globbing** je način da se odredi da bi se određeni parametar trebao spojiti (be matched) sa ostalim djelovima rute. Na primjer:

<pre><code>get 'photos/*other', to: 'photos#unknown'</code></pre>

Ova ruta će spojiti photos/12 i photos/long/path/to/12 podešavajući params[:other] na "12" ili "long/path/to/12". Fragmenti koji su prefiks zvijezdi se zovu 'wildcard segmenti'. Wildcard segmenti se mogu pojaviti bilo gdje u ruti.

<pre><code>get 'books/*section/:title', to: 'books#show'</code></pre>

A možemo imati i više od jednog wildcard segmenta:

<pre><code>get '*a/foo/*b', to: 'test#index'</code></pre>

a spojilo bi zoo/woo/foo/bar/baz gdje su params[:a] 'zoo/woo' i params[:b] bar/baz'.

Opcijom :format (true ili false) određujemo da li je format segment obavezan.

## 3.12 Redirekcija

Pomoću redirect helpera moguće je redirektovati bilo koju putanju:

<pre><code>get '/stories', to: redirect('/posts')</code></pre>

Mogu se ponovo koristiti i dinamički segmenti:

<pre><code>get '/stories/:name', to: redirect('/posts/%{name}')</code></pre>

A mogu se koristiti i blokovi, koji će primiti parametre i request objekat:

<pre><code>get '/stories/:name', to: redirect {|params, req| "/posts/#{params[:name].pluralize}" }
get '/stories', to: redirect {|p, req| "/posts/#{req.subdomain}" }</code></pre>

## 3.14 Korišćenje root

Sa root metodom možemo odrediti šta je Rails da rutira sa '/':

<pre><code>root to: 'pages#main'
root 'pages#main' # shortcut for the above</code></pre>

Root ruta bi se trebala nalaziti na vrhu fajla. Root metoda se može koristiti unutar namespace-ova i scope-ova.

## 3.15 Rutiranje Unicode karaktera

Rute sa Unicode karakterima se mogu definisati direktno:

<pre><code>get 'こんにちは', to: 'welcome#index'</code></pre>

# 4 Prilagođavanje Resourceful ruta

## 4.1 Određivanje kontrolera za korišćenje

:controller opcija omogućava određivanja kontrolera koji će se koristiti za određeni resurs. Na primjer:

<pre><code>resources :photos, controller: 'images'</code></pre>

će prepoznati dolazne putanje koje počinju sa /photos ali rutirati na Images kontroler:

|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Helper**|
|GET|/photos|index|photos_path|
|GET|/photos/new|new|new_photo_path|
|POST|/photos|create|photo_path|
|GET|/photos/:id|show|photo_path(:id)|
|GET|/photos/:id/edit|edit|edit_photo_path(:id)|
|PATCH/PUT|/photos/:id|update|photo_path(:id)|
|DELETE|/photos/:id|destroy|photo_path(:id)|

Za kontrolere unutar namespace, koristi se notacija sa direktorijumima:

<pre><code>resources :user_permissions, controller: 'admin/user_permissions'</code></pre>

## 4.2 Određivanje ograničenja

Možemo koristiti opciju :constraints da zahtijevamo određeni format za id. Na primjer:

<pre><code>resources :photos, constraints: {id: /[A-Z][A-Z][0-9]+/}</code></pre>

Ako želimo da jedno ograničenja primijenimo na više ruta, koristimo blok:

<pre><code>constraints(id: /[A-Z][A-Z][0-9]+/) do
  resources :photos
  resources :accounts
end</code></pre>

## 4.3 Preklapanje imena helpera

Opciju :as možemo koristiti ako želimo da predefinišemo normalno imenovanje helpera. Na primjer:

<pre><code>resources :photos, as: 'images'</code></pre>

će prepoznati dolaznu putanju koja počinje sa /photos i rutirati zahtjev na PhotosController, ali će koristiti vrijednost :as opcije za imenovanje helpera:

|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Helper**|
|GET|/photos|index|images_path|
|GET|/photos/new|new|new_image_path|
|POST|/photos|create|image_path|
|GET|/photos/:id|show|image_path(:id)|
|GET|/photos/:id/edit|edit|edit_image_path(:id)|
|PATCH/PUT|/photos/:id|update|image_path(:id)|
|DELETE|/photos/:id|destroy|image_path(:id)|

## 4.4 Preklapanje new i edit segmenata

:path_names opcija omogućava preklapanje automatski generisanih "new" i "edit" segmenata u putanji:

<pre><code>resources :photos, path_names: { new: 'make', edit: 'change' }</code></pre>

Ovo će prouzrokovati to da rutiranje prepozna putanje kao:

<pre><code>/photos/make
/photos/1/change</code></pre>

## 4.5 Prefiksi imena helpera

Opciju :as možemo koristi i da dodamo prefiks imenima helpera koje Rails generiše. Ovu opciju treba koristiti da se izbjegne eventualno preklapanje između ruta korišćenjem path scope-a. Na primjer:

<pre><code>scope 'admin' do
  resources :photos, as: 'admin_photos'
end
 
resources :photos</code></pre>

Dobićemo helpera admin_photos_path, new_admin_photo_path itd.

Da dodamo prefiks grupi route helpera, koristimo :ad sa scope-om:

<pre><code>scope 'admin', as: 'admin' do
  resources :photos, :accounts
end
 
resources :photos, :accounts</code></pre>

Ovo će generisati rute poput admin_photos_path i admin_account_path koje mapiraju /admin/photos i /admin/accounts.

Prefiks se može dodati i rutama sa imenovanima parametrom:

<pre><code>scope ':username' do
  resources :posts
end</code></pre>

što će rezultovati URL adresama kao /bob/posts/1 i dozvoliti referenciranje username dijela putanje kao params[:username] u kontrolerima, helperima i view fajlovima.

## 4.6 Restrikcija kreiranih ruta

Po defaultu, Rails kreira rute za sedam default akcija (index, show, new, create, edit, update i destroy) za svaki rutu u aplikaciji. Možemo koristiti :only i :except opcije da unaprijedimo prethodno rečeno. Opcija :only govori Railsu koje putanje jedino da kreira:

<pre><code>resources :photos, only: [:index, :show]</code></pre>

Sada, GET zahtjev za /photos bi uspio, ali POST zahtjev za /photos (koji bi inače bio rutiran na create akciju) ne bi uspio.

Opcija :except određuje koje rute se neće kreirati:

<pre><code>resources :photos, except: :destroy</code></pre>

## 4.7 Prevedene putanje

Korišćenjem scope-a, možemo promijeniti imena putanja generisana od resursa:

<pre><code>scope(path_names: { new: 'nova', edit: 'izmjena' }) do
  resources :categories, path: 'kategorija'
end</code></pre>

Rails sada kreira rute za CategoriesController:

|  |  | | |
| -----------------------| -------------------| --------------- |--------------- |
|**HTTP glagol**|**Putanja**|**Akcija**|**Helper**|
|GET|/kategorija|index|categories_path|
|GET|/kategorija/nova|new|new_category_path|
|POST|/kategorija|create|category_path|
|GET|/kategorija/:id|show|category_path(:id)|
|GET|/kategorija/:id/izmjena|edit|edit_category_path(:id)|
|PATCH/PUT|/kategorija/:id|update|category_path(:id)|
|DELETE|/kategorija/:id|destroy|category_path(:id)|

## 4.8 Preklapanje forme u jednini

Ako želimo da definišemo resurs u jednini, dodajemo dodatna pravila na Inflector:

<pre><code>ActiveSupport::Inflector.inflections do |inflect|
  inflect.irregular 'tooth', 'teeth'
end</code></pre>

## Korišćenje :as u Nested resursima

Opcija :as preklapa automatski generisano ime resursa u ugnježdenim rutama helpera.

<pre><code>resources :magazines do
  resources :ads, as: 'periodical_ads'
end</code></pre>

Ovo će kreirati helpere kao magazine_periodical_ads_url i edit_magazine_periodical_ad_path

# 5 Inspekcija i testiranje ruta

## 5.1 Spisak postojećih ruta

Za dobijanje liste svih dostupnih ruta u aplikaciji, posjetiti <code>http://localhost:3000/rails/info/routes</code> u browseru dok server radi u **development** okruženju. Isti rezultate možemo dobiti komandom <code>rake routes</code> u terminalu.

Takođe je moguće ograničiti štampanje spiska svih postojećih ruta na određen kontroler podešavanjem CONTROLLER promjenljive okruženja:

<pre><code>$ CONTROLLER=users rake routes</code></pre>

## 5.1 Testiranje ruta

Rails nudi tri ugrađene metode potvrde (assertions) koje olakšavaju testiranje ruta:

* <code>assert_generates</code>
* <code>assert_recognizes</code>
* <code>assert_routing</code>

### 5.1.1 assert_generates

<code>assert_generates</code> potvrđuje da određen skup opcija generiše određenu putanju i da se može koristiti sa default rutom ili nekom predefinisanom rutom:

<pre><code>assert_generates '/photos/1', { controller: 'photos', action: 'show', id: '1' }
assert_generates '/about', controller: 'pages', action: 'about'</code></pre>

### 5.1.2 assert_recognizes

<code>assert_recognizes</code> je suprotna <code>assert_generates</code>. Potvrđuje da je određena putanja prepoznata i da rutira na određeno mjesto u aplikaciji. 

<pre><code>assert_recognizes({ controller: 'photos', action: 'show', id: '1' }, '/photos/1')</code></pre>

Argument :method se može koristiti da se odredi HTTP glagol:

<pre><code>assert_recognizes({ controller: 'photos', action: 'create' }, { path: 'photos', method: :post })</code></pre>

### 5.1.3 assert_routing

<code>assert_routing</code> provjerava rutu u oba pravca: testira da li putanja generiše opcije i da li opcije generišu putanju.

<pre><code>assert_routing({ path: 'photos', method: :post }, { controller: 'photos', action: 'create' })</code></pre>