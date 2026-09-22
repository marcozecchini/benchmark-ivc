# TransLog — IVC benchmark: Plonky2 vs Sonobe vs Nova/Spartan su una catena SHA-256

Workspace Rust che confronta tre approcci di **Incremental Verifiable Computation (IVC)**
sulla stessa logica di circuito — un singolo blocco SHA-256 su 32 byte, dove l'output di
uno step diventa l'input dello step successivo (`z_{i+1} = SHA-256(z_i)`):

| | Plonky2 | Sonobe | Nova (Microsoft) + Spartan |
|---|---|---|---|
| **Schema** | Ricorsione ciclica nativa STARK/FRI: ogni step verifica in-circuito la prova dello step precedente | Folding Nova + CycleFold: ogni step *accumula* l'istanza R1CS senza generare uno SNARK completo | Folding Nova (implementazione di riferimento, `nova-snark`): accumulazione per step |
| **Campo / curve** | Goldilocks (64 bit, `p = 2^64 − 2^32 + 1`), massimamente hardware-friendly su CPU a 64 bit | Ciclo di curve BN254/Grumpkin (il ciclo 2-cycle nativamente supportato e più efficiente in Sonobe per CycleFold) | Ciclo BN254/Grumpkin via halo2curves (**scelto empiricamente**: più veloce del ciclo Pasta nel proving, vedi sotto) |
| **Hash ricorsione / trascritto** | Poseidon su Goldilocks (`PoseidonGoldilocksConfig`, l'hasher algebrico nativo di Plonky2 per la ricorsione) | Sponge Poseidon su Fr di BN254 per il trascritto Fiat-Shamir | Poseidon (Neptune) per gli hash ricorsivi |
| **Commitment** | Merkle/FRI (trasparente, nessun trusted setup) | KZG su BN254 (curva primaria) + Pedersen su Grumpkin (curva CycleFold) | Pedersen su entrambe le curve (trasparente) |
| **Prova finale** | L'ultima prova ricorsiva è già la prova finale succinta | Serve un **Decider**: Groth16 + KZG comprime l'istanza accumulata in uno SNARK finale (misurato separatamente) | **Spartan + IPA** (`CompressedSNARK`): compressione trasparente, **nessun trusted setup**, prova ~centinaia di KB |

I tre stack sono configurati in modo **totalmente indipendente**, ciascuno con il proprio
setup crittografico ottimale, a parità di logica del circuito (stessa catena SHA-256,
verificata a fine run contro l'implementazione nativa `sha2`).

## Struttura

```
crates/
  bench-common/      Allocatore globale di conteggio (picco RAM per fase) + modello del report
  plonky2-ivc/       Gadget SHA-256 bit-level per Plonky2 + IVC a ricorsione ciclica
  sonobe-ivc/        FCircuit SHA-256 (gadget arkworks) + Nova/CycleFold + DeciderEth
  nova-spartan-ivc/  StepCircuit SHA-256 (gadget bellpepper) + nova-snark + Spartan/IPA
                     (+ benches/merkle_benchmark.rs: IVC di append su Merkle tree, vedi sotto)
  hypernova-pcd/     PCD ad albero binario: HyperNova multifolding (MU=2), merge di accumulatori
  ivc-bench/         Harness: benches/ivc_benchmark.rs (+ binario gemello per cargo run)
```

Dettagli implementativi:

- **Plonky2** (`crates/plonky2-ivc`): SHA-256 implementato a livello di bit
  (`BoolTarget`, parole a 32 bit LSB-first) con XOR/CH/MAJ come operazioni aritmetiche
  impacchettate e addizioni mod 2^32 tramite `split_le`. La `CommonCircuitData` ciclica è
  ottenuta per **punto fisso**: si costruisce il circuito iterativamente finché la forma
  del circuito che verifica sé stesso converge (tipicamente 2–3 iterazioni, degree 2^13).
  Ogni step produce una prova ricorsiva completa; input pubblici = stato iniziale,
  stato corrente, contatore, verifier key ciclica.
- **Sonobe** (`crates/sonobe-ivc`): stato IVC = 32 elementi di campo (un byte ciascuno);
  ogni step ricompone i byte (8 vincoli booleani + 1 uguaglianza lineare per byte),
  applica il gadget SHA-256 di `ark-crypto-primitives` e restituisce i 32 byte del digest.
  Il tempo del **passo di folding** (accumulazione) è tracciato separatamente dal tempo
  del **Decider** finale (Groth16 + KZG) e dal relativo keygen.
- La dipendenza `folding-schemes` è pinnata alla revisione `839db0c` (14 feb 2025) di
  Sonobe: è l'ultima in cui il circuito **completo** del `DeciderEth` (Groth16+KZG)
  verifica correttamente su arkworks 0.5 stabile. Il commit successivo (`e9bebdb`,
  PR #203) introduce un fork "perf" di `ark-r1cs-std` e rompe il percorso completo del
  decider (`SNARKVerificationFail`) — regressione non rilevata dalla CI di Sonobe, che
  testa il decider solo con la feature `light-test` (che salta la parte pesante del
  circuito). La ristrutturazione successiva del repo (`v0.1.0-alpha.1`) non espone
  ancora un decider SNARK concreto. Nota: Sonobe non integra Spartan come decider
  (è solo citato nel README come possibilità futura); l'unico SNARK plug-in
  compatibile con il trait arkworks è Groth16 — per questo il confronto con Spartan
  usa l'implementazione di riferimento di Microsoft (backend `nova-spartan-ivc`).
- **Nova/Spartan** (`crates/nova-spartan-ivc`): `nova-snark` 0.75 (microsoft/Nova).
  Stato IVC identico a Sonobe (32 elementi = 32 byte); il circuito decompone i byte in
  bit, applica il gadget SHA-256 del frontend bellpepper vendorizzato e riimpacchetta il
  digest (~40k vincoli per step sul circuito primario). Il runner è generico sul ciclo di
  curve; la compressione finale è **Spartan con IPA-PC su entrambe le curve** (pipeline
  interamente trasparente). Nota: il primo `prove_step` di nova-snark è il caso base ed è
  quasi gratuito (`min ≈ 0 ms` nel report).

### Confronto per-step misurato (N=10)

Tempo del solo **passo ricorsivo** (prova ricorsiva completa per Plonky2, passo di
folding per Sonobe e Nova), misurato su questa macchina (Xeon Platinum 8592+,
`target-cpu=native`, N=10):

| backend | avg | min | max | vs più veloce |
|---|---|---|---|---|
| **Nova (Microsoft) + Spartan** | **577 ms** | ~0 ms¹ | 803 ms | **1.00×** |
| Sonobe (Nova IVC + CycleFold, Decider Groth16) | 635 ms | 528 ms | 692 ms | 1.10× |
| Plonky2 (ricorsione ciclica) | 1.134 s | 1.066 s | 1.279 s | 1.97× |

¹ Il primo `prove_step` di nova-snark è il caso base ed è quasi gratuito; il primo
step di Plonky2 include invece la verifica della base proof dummy (stesso costo dei
successivi).

I due schemi a folding costano circa la metà di una prova ricorsiva completa per
step; Plonky2 recupera altrove (nessun SNARK finale, verifica in millisecondi),
ma quel confronto esula dal costo del passo ricorsivo.

### Scelta della curva per Nova/Spartan

Misurata su questa macchina (Xeon Platinum 8592+, N=10, `target-cpu=native`):

| ciclo | prove_step (avg) | setup | Spartan finale |
|---|---|---|---|
| **BN254/Grumpkin (default)** | **368 ms** | **15.2 s** | **34.0 s** |
| Pasta (Pallas/Vesta) | 389 ms | 58.3 s | 37.9 s |

BN254/Grumpkin (halo2curves, con aritmetica asm) vince su tutte le metriche ed è il
default; `--nova-curve pasta` seleziona il ciclo Pasta. Attenzione: il profilo release
del workspace forza `lto = "off"` perché qualsiasi inlining LTO (anche il thin-LTO
locale di rustc) combinato con `-C target-cpu=native` rompe l'assembly inline di
halo2curves ("inline assembly requires more registers than available").

### Benchmark Merkle append su Nova+Spartan (`merkle_benchmark`)

Oltre alla catena SHA-256, il crate `nova-spartan-ivc` contiene un secondo caso d'uso
IVC: **ad ogni step di folding viene aggiunta una foglia a un Merkle tree e la root
viene aggiornata**, con compressione finale Spartan+IPA (trasparente).

L'albero è **incrementale in stile "frontier"** (la costruzione append-only standard di
Semaphore/Tornado): lo stato IVC porta, per ciascun livello, la radice del sottoalbero
pieno più a destra. L'append della foglia con indice `i` percorre i `d` livelli una
volta sola: al livello `j` il bit `j` di `i` seleziona il sibling (nodo di frontier se
1, costante zero-subtree se 0, nel qual caso la frontier di quel livello viene
aggiornata). Un append = `d` hash SHA-256 su input da 64 byte (2 blocchi di
compressione l'uno), deterministico — nessun witness di authentication path.

Dettagli del circuito (`crates/nova-spartan-ivc/src/merkle.rs`):

- **Stato IVC** (`3 + 2d` elementi): `[indice, root_hi, root_lo, frontier_0_hi,
  frontier_0_lo, …]` — ogni digest da 32 byte è impacchettato big-endian in 2 elementi
  da 128 bit (il vincolo di packing fa anche da range check); il vincolo di
  decomposizione dell'indice impone `indice < 2^d`.
- La **foglia** è advice non deterministica portata dall'istanza di circuito per-step
  (l'enunciato provato è "esiste una sequenza di `n` foglie il cui append in ordine
  produce `root_n`"); a fine run l'intero stato (indice, root e frontier) è confrontato
  con l'albero incrementale nativo `sha2`, a sua volta testato contro la root del
  full tree classico su foglie zero-padded.
- **Costo**: lo step cresce linearmente con la profondità (`d` SHA-256 a 2 blocchi,
  ~80k vincoli l'uno): a `--depth 32` (default, capacità 2^32 foglie) il circuito
  primario è multi-milione di vincoli — setup e Spartan finale richiedono minuti e
  parecchi GiB. Per run rapide usare `--depth 8,16` e/o `--skip-spartan`.

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench -p nova-spartan-ivc --bench merkle_benchmark -- --steps 10 --depth 32

# sweep di profondità senza SNARK finale
RUSTFLAGS="-C target-cpu=native" cargo bench -p nova-spartan-ivc --bench merkle_benchmark -- --steps 10 --depth 8,16,32 --skip-spartan

# ciclo Pasta
RUSTFLAGS="-C target-cpu=native" cargo bench -p nova-spartan-ivc --bench merkle_benchmark -- --steps 10 --depth 16 --nova-curve pasta
```

Il report per (depth, N) separa setup, tempo per step (avg/min/max/totale), Spartan
finale, verifica e picco RAM per fase, e stampa la root finale (identica a quella
nativa per costruzione del cross-check).

## Compilazione ed esecuzione

Compilare **sempre** con i flag hardware nativi: entrambi gli stack traggono grande
beneficio da AVX2/AVX-512 (Goldilocks a 64 bit, campo di BN254, NTT/MSM):

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench -p ivc-bench -- --steps 10,50,100
```

Varianti:

```bash
# Senza gli stadi di SNARK finale (Decider Groth16 di Sonobe e Spartan di Nova)
RUSTFLAGS="-C target-cpu=native" cargo bench -p ivc-bench -- --steps 10 --skip-decider

# Un solo backend
RUSTFLAGS="-C target-cpu=native" cargo bench -p ivc-bench -- --steps 50 --only plonky2
RUSTFLAGS="-C target-cpu=native" cargo bench -p ivc-bench -- --steps 50 --only sonobe
RUSTFLAGS="-C target-cpu=native" cargo bench -p ivc-bench -- --steps 50 --only nova

# Ciclo di curve alternativo per Nova/Spartan
RUSTFLAGS="-C target-cpu=native" cargo bench -p ivc-bench -- --steps 50 --only nova --nova-curve pasta

# Equivalente via binario
RUSTFLAGS="-C target-cpu=native" cargo run --release -p ivc-bench -- --steps 10
```

Test di correttezza (catena in-circuito ≡ catena nativa `sha2`):

```bash
RUSTFLAGS="-C target-cpu=native" cargo test --release --workspace
```

## PCD ad albero (crate `hypernova-pcd`)

Oltre alle tre catene IVC, il workspace contiene una **PCD (Proof-Carrying Data) ad
albero binario** costruita su **HyperNova di Sonobe** con multifolding MU=2/NU=1 su
BN254/Grumpkin — l'unico framework del confronto in cui la fusione di **due accumulatori
in uno** è supportata e verificata **in-circuito** (in nova-snark l'operazione esiste
solo come primitiva fuori circuito, `NIFSRelaxed`).

L'albero è **n-ario** (`--arity 2,4,8,16`): un nodo folda MU = n accumulatori con un
**singolo sum-check** (round e grado indipendenti da n — la proprietà chiave del
multifolding), quindi allargare i nodi ammortizza l'overhead fisso di ricorsione su più
dati. Misurato a parità di dati (~2 KiB, Xeon 8592+):

| arità | nodi | merge/nodo | setup | throughput dati | vs binario |
|---|---|---|---|---|---|
| 2 | 63 | 2.8 s | 12 s / 0.8 GiB | 16 B/s | 1.0× |
| 4 | 21 | 4.2 s | 14 s / 1.2 GiB | 49 B/s | 3.0× |
| **8** | 9 | 10.2 s | 29 s / 4.0 GiB | **90 B/s** | **5.5×** |
| 16 | 17 (8 KiB) | 30.2 s | 65 s / 14.0 GiB | 106 B/s | 6.5× |

Lo **sweet spot pratico è l'arità 8**: a 16 il guadagno marginale (+18%) non ripaga
l'esplosione di setup, RAM (22 GiB di picco sull'albero) e costo del merge — la parte
lineare in n (SHA di 32n byte, n punti CycleFold) ha ormai superato l'overhead fisso
che l'arità ammortizza.

### Configurazione di default

I tre benchmark (`pcd_benchmark`, `update_benchmark`, `batch_update_benchmark`) senza
flag usano **arità di folding MU=4, senza bucket (W=4, nodi da 128 B)**: le metriche
che guidano il progetto sono i tempi di **update** (singolo e multiplo), e su quelle il
bucketing peggiora (~1.7×: il merge hasha padding inutile e costa più di quanto accorci
il cammino). `--bucket-words 8/16/32/64` (bucket 256B/512B/1KiB/2KiB, arità 4) resta
disponibile per i carichi di **costruzione bulk**, dove rende 2.4–3.3×.

### Bucketing alla Reckle (`--bucket-words W`)

Leva ortogonale all'arità: si disaccoppia la **larghezza del nodo** W (byte hashati =
32·W) dall'**arità di folding** MU (fissata a 4). La foglia ingerisce un intero bucket
di 32·W byte in un solo step; i merge foldano sempre MU accumulatori, con l'input di
hash zero-paddato a 32·W (circuito uniforme). Misurato (costruzione albero, MU=4):

| bucket/nodo | s/nodo | throughput | vs baseline |
|---|---|---|---|
| 128 B (baseline W=4) | 1.80 | 53 B/s | 1.0× |
| 512 B | 3.03 | 128 B/s | 2.4× |
| **1 KiB** | 4.95 | **157 B/s** | **3.0×** |
| 2 KiB | 8.86 | 176 B/s | 3.3× |

L'overhead fisso di ricorsione (~250k vincoli) si ammortizza su più dati per nodo;
i rendimenti calano quando il costo SHA domina (e setup/RAM crescono: 67 s / 21 GiB
a 2 KiB). **Sweet spot: bucket 1 KiB (3×)**. Nota: allargare l'hash rende molto più
che allargare il folding — bucket 2 KiB (176 B/s) batte l'8-ario puro (90 B/s) di 2×.
Contropartita per gli update: ogni nodo del cammino costa di più (l'update singolo
peggiora), mentre il costo *per byte aggiornato* migliora — il bucket va scelto in
base al rapporto letture/scritture del carico.

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd --bench pcd_benchmark -- --arity 4 --bucket-words 32 --depth 2
```

Semantica (un Merkle tree n-ario su blocchi dati di 32·n byte):

- funzione di step uniforme per ogni nodo: `z' = SHA-256(z ‖ ext)` con `z` = 32 byte e
  `ext` = 32·(n−1) byte;
- **foglia**: `z₀` = primi 32 byte del blocco dati, `ext` = i restanti; folda n−1
  accumulatori banali (dummy a i=0, come il passo base di Sonobe);
- **nodo interno**: continua la catena del primo figlio (`z` = suo digest,
  `ext` = digest degli altri n−1) e **folda gli n−1 accumulatori fratelli**
  (`(U_i, W_i)` passati via `other_instances` di `prove_step`);
- la radice viene verificata con `HyperNova::verify` e confrontata con la Merkle root
  n-aria nativa (`sha2`); Decider finale (Groth16+KZG) opzionale (`--decider`)
  sull'accumulatore della radice.

```bash
# confronto di arità a parità di dati (~2 KiB per albero)
RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd -- --arity 2,4,8

# singola arità, profondità scelta, con SNARK finale
RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd -- --arity 8 --depth 1 --decider
```

Il report separa: tempo per nodo aggregato per livello, verifica nativa dei fratelli
prima del merge (`--no-sibling-check` per disattivarla), Decider finale, RAM per fase.

**Bug upstream corretto localmente**: il Decider di HyperNova in Sonobe panica al
keygen Groth16 per MU > 1 ("index out of bounds" in `compute_c_gadget`): il circuito
del decider verifica sempre un fold NIMFS 1×1 (`U_i + u_i`), ma il proof dummy usato
per il setup viene sagomato con (MU, NU) — e upstream il decider è testato solo con
MU = NU = 1. Il workspace usa una copia vendorizzata di `folding-schemes` con il fix
da una riga (`third_party/sonobe-839-patched`, agganciata via `[patch]`; vale per
entrambi i crate Sonobe, senza effetti sul decider di Nova che è già 1×1). Il runner
mantiene inoltre un retry difensivo con snapshot attorno a `prove_step` (mai
scattato nelle run osservate; i retry sarebbero conteggiati nel report).

### Update di una foglia in stile Reckle Trees (`update_benchmark`)

Ispirato a [Reckle Trees (eprint 2024/493)](https://eprint.iacr.org/2024/493): ogni nodo
dell'albero mantiene il proprio accumulatore; aggiornare una foglia richiede di
riprovare **solo il cammino foglia→radice** (O(log_n N) nodi), foldando gli accumulatori
*immutati* dei fratelli. Lo stato iniziale usa foglie identiche, così un rappresentante
per livello (clonato sui fratelli) è un albero di accumulatori valido e il cross-check
con la Merkle root nativa resta esatto; l'update misurato è proving reale al 100%.

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd --bench update_benchmark -- --arity 2,4,8,16 --leaves 4096
```

Risultati per l'update di 1 foglia in un albero di 2^12 = 4096 foglie (Xeon 8592+):

| arità | profondità | nodi cammino | merge/nodo | **latenza update** |
|---|---|---|---|---|
| 2 | 12 | 13 | 2.7 s | 34.2 s |
| **4** | 6 | 7 | 3.6 s | **22.8 s** |
| 8 | 4 | 5 | 9.9 s | 41.1 s |
| 16 | 3 | 4 | 29.6 s | 1m32s |

**L'arità ottimale dipende dall'operazione**: per la *costruzione* dell'albero intero
vince l'arità 8 (throughput, vedi sopra); per gli *update* vince l'arità 4 — il costo è
profondità × costo-merge, e oltre l'arità 4 la crescita del merge (lineare-e-più in n)
supera il risparmio di profondità (logaritmico).

### Aggiornamenti multipli (k foglie per volta) e limiti di scala

Punti misurati su N = 2^32 foglie, arità 4 (256 core; "unione" = nodi distinti dei k
cammini foglia→radice, riprovati per livello a ondate di 32 task × 8 thread):

| k | nodi unione | wall | per-update ammortizzato |
|---|---|---|---|
| 1 | 17 | ~59 s (est. da 2^12: 22.8 s a prof. 6) | 59 s |
| 16 | 238 | 2m56s | 11.0 s |
| 256 | 3.295 | 34m29s | 8.1 s |
| 2^19 (estrapolato) | ~3,8 M | **~28 giorni** | ~4.6 s |

Il throughput della macchina è l'invariante: **~1,6 nodi/s** qualunque sia k (il
parallelismo per livello arriva a ~30× con le ondate, ma il lavoro per nodo si gonfia
in proporzione). Da qui il limite: un regime "WhatsApp Key Transparency" (~75.000
update/min su un albero ~2^37, vedi Aegon eprint 2026/1681 §1.2) richiederebbe
~16.000 nodi/s — 4 ordini di grandezza oltre questa macchina — più ~15 TB di RAM per
gli accumulatori delle foglie. A quella scala serve un cambio di schema (lavoro per
epoca ∝ update senza fattore ×profondità, come fa Aegon), non un'ottimizzazione dei
nodi; il regime "singolo shard" (~10 update/min) è invece alla portata di questo stack.

### Esperimento GPU (rimosso)

È stata sperimentata (e poi **rimossa** su decisione di progetto) un'integrazione
ICICLE/CUDA che offloadava su GPU le MSM dei commitment e il prover del sum-check.
Risultati misurati su NVIDIA L4 vs 256 core, con radici sempre identiche ai run CPU:
MSM isolata 35×, sum-check 8.9× (2.30 → 0.26 s), step di merge 2.2×, update singolo
1.6× — ma **nessun guadagno nel regime multi-update parallelo** (i 256 core restano il
collo e una sola GPU fa da imbuto ai worker). Su questa macchina la GPU compra latenza
del cammino sequenziale, non throughput aggregato: da qui la rimozione. Il codice non è
più nel repo; design, numeri e insidie d'integrazione restano documentati per un
eventuale ripristino su hardware diverso (pochi core CPU o GPU datacenter).

**Caveat di soundness (importante)**: Sonobe espone HyperNova come *IVC con
multifolding*: il circuito aumentato vincola la storia di catena (contatore, z₀→zᵢ)
solo per l'accumulatore principale. Le istanze extra foldate sono provate *valide*
(soddisfano la relazione del circuito aumentato) ma il loro legame applicativo
("l'input del padre è l'output dei figli") e il loro accumulatore CycleFold non sono
vincolati in-circuito di serie. Il benchmark compensa verificando nativamente la prova
IVC di ogni fratello destro prima del merge (misurato a parte); una PCD completa
richiederebbe di estendere il circuito aumentato di Sonobe.

## Cosa viene misurato

Per ogni `N` richiesto e per ciascun backend il report finale confronta:

- **setup latency** — costo una tantum: per Plonky2 la ricerca del punto fisso della
  circuit data ciclica + la base proof dummy; per Sonobe `Nova::preprocess` + keygen del
  Decider (Groth16 + KZG) + `Nova::init`.
- **step proving** — tempo per step (media/min/max/totale): prova ricorsiva completa per
  Plonky2, passo di folding (accumulazione) per Sonobe. Cronometrato con
  `std::time::Instant`.
- **final SNARK** — Sonobe: `Decider::prove` (Groth16 finale, richiede trusted setup);
  Nova/Spartan: `CompressedSNARK::prove` (Spartan+IPA, trasparente). Per Plonky2 è
  `n/a`: l'ultima prova ricorsiva è già la prova finale.
- **RAM** — picco di heap vivo per fase, misurato da un allocatore globale di conteggio
  (`bench-common::PeakAllocator`), quindi *byte effettivamente allocati*, non RSS.
- **verification** — verifica della prova finale (sanity check di ogni run).

Note di lettura dei risultati:

- Il confronto per-step è il cuore del benchmark: Nova ammortizza il costo evitando di
  generare uno SNARK a ogni passo, Plonky2 paga ogni step come prova completa ma non ha
  alcun costo finale né trusted setup.
- Il primo step di Plonky2 include la verifica della base proof dummy (stesso costo dei
  successivi); il primo step di Sonobe è tipicamente più economico (istanza accumulata
  ancora banale).
- Il keygen del Decider di Sonobe domina la latenza di setup: usare `--skip-decider` per
  confrontare il solo loop IVC.
