import socket
import string
from ipaddress import ip_address, IPv4Address 

#Validar dirección IP
def validIPAddress(IP: str) -> str: 
    try: 
        return "IPv4" if type(ip_address(IP)) is IPv4Address else "IPv6"
    except ValueError: 
        return "Invalida"




#Definir Socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("lo", 0))

origen_correcto = 0
destino_correcto = 0

#IP Origen Dinámica
ip_o = input('Ingrese la Dirección IP de origen: ')




#Verificar validez de la IP
while origen_correcto == 0:
    if validIPAddress(ip_o)=="IPv4":
        ip_o = input('Error: ingrese una Dirección IPv6: ')
    elif validIPAddress(ip_o)=="IPv6":
        origen_correcto = 1
    else:
        ip_o = input('Error: ingrese una Dirección IP válida: ')

origen_correcto == 0

ip_o_separada = ip_o.split(':')

while origen_correcto == 0:
    if len(ip_o_separada)==8:
        origen_correcto = 1
    else:
         ip_o = input('Error: ingrese una Dirección IP con el formato xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx ')


#unir de dos en dos para crear bits luego
ip_o_separada=''.join(ip_o_separada)
ip_o_separada = [ip_o_separada[i:i+2] for i in range(0, len(ip_o_separada), 2)]

#Unir de 4 en 4 para TCP Checksum
ip_origen_check=ip_o_separada.copy()
ip_origen_check=''.join(ip_origen_check)
ip_origen_check = [ip_origen_check[i:i+4] for i in range(0, len(ip_origen_check), 4)]

i=0
for _ in ip_o_separada:
    ip_o_separada[i]="0x"+ip_o_separada[i]
    i+=1


#Converitr IP a hex
i = 0
for _ in ip_o_separada:
    ip_o_separada[i]='0x{:02X}'.format(int(ip_o_separada[i],16))
    i += 1
    
#print(ip_o_separada)

#print(bytes([int(x,0) for x in ip_o_separada]))

#IP Destino Dinámica
ip_d = input('Ingrese la Dirección IP de destino: ')



#print(len(ip_d_separada))


#Verificar validez de la IP
while destino_correcto == 0:
    if validIPAddress(ip_d)=="IPv4":
        ip_d = input('Error: ingrese una Dirección IPv6: ')
    elif validIPAddress(ip_d)=="IPv6":
        destino_correcto = 1
    else:
        ip_d = input('Error: ingrese una Dirección IP válida: ')


ip_d_separada = ip_d.split(':')



destino_correcto == 0
print(destino_correcto)
print(len(ip_d_separada))

while destino_correcto == 0:
    if len(ip_d_separada)==8:
        destino_correcto = 1
    else:
         ip_d = input('Error: ingrese una Dirección IP con el formato xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx ')


#Unir de 2 en 2 para luego pasar a bits
ip_d_separada=''.join(ip_d_separada)
ip_d_separada = [ip_d_separada[i:i+2] for i in range(0, len(ip_d_separada), 2)]

#Unir de 4 en 4 para TCP Checksum
ip_destino_check=ip_d_separada.copy()
ip_destino_check=''.join(ip_destino_check)
ip_destino_check = [ip_destino_check[i:i+4] for i in range(0, len(ip_destino_check), 4)]


i=0
for _ in ip_d_separada:
    ip_d_separada[i]="0x"+ip_d_separada[i]
    i+=1

#Converitr IP a hex
i = 0
for _ in ip_d_separada:
    ip_d_separada[i]='0x{:02X}'.format(int(ip_d_separada[i],16))
    i += 1

#Definición MAC de destino, MAC de origen y Protocolo  Ethernet
ethernet  = b'\x00\x0c\x29\xd3\xbe\xd6' # Dirección MAC de Destino
ethernet += b'\x00\x0c\x29\xe0\xc4\xaf' # Dirección MAC de Origen
ethernet += b'\x86\xdd'                 # Protocolo IPv6

#Definir los hex para la cabecera IP
ip_header_row1=["0x60","0x00","0x00","0x01"]
ip_header_row2=["0x14","0x06","0x06","0x00"]




#Armar IP Header
ip_header  = bytes([int(x,16) for x in ip_header_row1]) 
ip_header += bytes([int(x,16) for x in ip_header_row2])  
ip_header += bytes([int(x,0) for x in ip_o_separada])  # Source Address
ip_header += bytes([int(x,0) for x in ip_d_separada])   # Destination Address



#Definir los hex para el paquete
tcp_header_row1=["0x30","0x39","0x00","0x50"]
tcp_header_row2=["0x00","0x00","0x00","0x00"]
tcp_header_row3=["0x00","0x00","0x00","0x00"]
tcp_header_row4=["0x50","0x02","0x71","0x10"]
tcp_header_row5_minusckeck=["0x00","0x00"]


#Protocolo y TCP Length
tcp_prot = "0x0006"
tcp_length = "0x0014"

#Unión de los componentes del paquete (sin Check)
checksumList2=tcp_header_row1+tcp_header_row2+tcp_header_row3+tcp_header_row4+tcp_header_row5_minusckeck

#print("Header: ")
#print(checksumList2)


#Separar cada hex eliminando el '0x' de cada uno.
i=0
for _ in checksumList2:
    checksumList2[i]=checksumList2[i][2:]
    i+=1

#Unir de dos en dos los hex para hacer el checksum
checksumList2=''.join(checksumList2)
checksumList2 = [checksumList2[i:i+4] for i in range(0, len(checksumList2), 4)]


checksumList2= checksumList2+ip_origen_check+ip_destino_check



print(ip_origen_check)
print(ip_destino_check)


#Agregar los caracteres '0x' a cada elemento de la lista del checksum
i=0
for _ in checksumList2:
    checksumList2[i]="0x"+checksumList2[i]
    i+=1


checksumList2.append(tcp_length)
checksumList2.append(tcp_prot)

#Calcular el checkusum tcp
tcp_checkshum=0
for i in range(0,len(checksumList2)):
    tcp_checkshum = int(checksumList2[i],16)+tcp_checkshum


#Negación con 0xffff
if tcp_checkshum > int('0xffff', 16):
    while tcp_checkshum > int('0xffff', 16):
        tcp_checkshum = tcp_checkshum - int('0xffff', 16)

tcp_checkshum = int('0xffff', 16) - tcp_checkshum
    

tcp_checkshum='0x{:04X}'.format(tcp_checkshum)
print("\nTCP Checksum: "+tcp_checkshum+"\n")

tcp_checkshum=tcp_checkshum[2:]

#Creación fila 5 con el checksum agregado
tcp_header_row5 = [tcp_checkshum[i:i+2] for i in range(0, len(tcp_checkshum), 2)]

i=0
for _ in tcp_header_row5:
    tcp_header_row5[i]="0x"+ tcp_header_row5[i]
    i+=1

tcp_header_row5 = tcp_header_row5 + tcp_header_row5_minusckeck


#print(tcp_header_row5)
#print(bytes([int(x,16) for x in tcp_header_row5]))


#Armar TCP
tcp_header  = bytes([int(x,16) for x in tcp_header_row1]) # Source Port | Destination Port
tcp_header += bytes([int(x,16) for x in tcp_header_row2]) # Sequence Number
tcp_header += bytes([int(x,16) for x in tcp_header_row3]) # Acknowledgement Number
tcp_header += bytes([int(x,16) for x in tcp_header_row4]) # Data Offset, Reserved, Flags | Window Size
tcp_header += bytes([int(x,16) for x in tcp_header_row5]) # Checksum | Urgent Pointer


#Unir Paquete
packet = ethernet + ip_header + tcp_header

#Enviar paquete
s.send(packet)


