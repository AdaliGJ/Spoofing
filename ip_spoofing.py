import socket
import string

#Definir Socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("lo", 0))

#IP Origen Dinámica
ip_o = input('Ingrese la Dirección IP de origen: ')
ip_o_separada = ip_o.split('.')


origen_correcto = 0
destino_correcto = 0

#Verificar validez de la IP
while origen_correcto == 0:
    if len(ip_o_separada)==4 and int(ip_o_separada[0])<=255 and int(ip_o_separada[1])<=255 and int(ip_o_separada[2])<=255 and int(ip_o_separada[3])<=255:
        origen_correcto = 1
    else:
        ip_o = input('Error: ingrese una Dirección IP válida: ')
        ip_o_separada = ip_o.split('.')

#Converitr IP a hex
i = 0
for _ in ip_o_separada:
    ip_o_separada[i]='0x{:02X}'.format(int(ip_o_separada[i]))
    #ip_o_separada[i]=hex(int(ip_o_separada[i]))
    i += 1
    
#print(ip_o_separada)

#print(bytes([int(x,0) for x in ip_o_separada]))

#IP Destino Dinámica
ip_d = input('Ingrese la Dirección IP de destino: ')
ip_d_separada = ip_d.split('.')


#print(len(ip_d_separada))


#Verificar Validez IP
while destino_correcto == 0:
    if len(ip_d_separada)==4 and int(ip_d_separada[0])<=255 and int(ip_d_separada[1])<=255 and int(ip_d_separada[2])<=255 and int(ip_d_separada[3])<=255:
        destino_correcto = 1
    else:
        ip_d = input('Error: ingrese una Dirección IP válida: ')
        ip_d_separada = ip_d.split('.')

i = 0
for _ in ip_d_separada:
    ip_d_separada[i]='0x{:02X}'.format(int(ip_d_separada[i]))
    i += 1
    #ip_d_separada[i]=hex(int(ip_d_separada[i]))
   
    
#print(ip_d_separada)

#print(bytes([int(x,0) for x in ip_d_separada]))

#Definición MAC de destino, MAC de origen y Protocolo  Ethernet
ethernet  = b'\x00\x0c\x29\xd3\xbe\xd6' # Dirección MAC de Destino
ethernet += b'\x00\x0c\x29\xe0\xc4\xaf' # Dirección MAC de Origen
ethernet += b'\x08\x00'                 # Protocolo IPv4

#Definir los hex para la cabecera IP
ip_header_row1=["0x45","0x00","0x00","0x28"]
ip_header_row2=["0xab","0xcd","0x00","0x00"]
ip_header_row3_minuscheck=["0x40","0x06"]
ip_origen_check=ip_o_separada.copy()
ip_destino_check=ip_d_separada.copy()



#Unión de los componentes del header del paquete (sin Direcciones Ip)
checksumList1=ip_header_row1+ip_header_row2+ip_header_row3_minuscheck

#Separar cada hex eliminando el '0x' de cada uno.
i=0
for _ in checksumList1:
    checksumList1[i]=checksumList1[i][2:]
    i+=1

#Unir de dos en dos los hex para hacer el checksum
checksumList1=''.join(checksumList1)
checksumList1 = [checksumList1[i:i+4] for i in range(0, len(checksumList1), 4)]


#Eliminar el x de los hex de la dirección IP de destino y de origen
i=0
for _ in ip_origen_check:
    ip_origen_check[i]=ip_origen_check[i].replace('0x', '')
    ip_destino_check[i]=ip_destino_check[i].replace('0x', '')
    i+=1


#Unir de dos en dos los hex de la dirección IP de origen y destino
ip_origen_check=''.join(ip_origen_check)
ip_destino_check=''.join(ip_destino_check)
ip_origen_check = [ip_origen_check[i:i+4] for i in range(0, len(ip_origen_check), 4)]
ip_destino_check = [ip_destino_check[i:i+4] for i in range(0, len(ip_destino_check), 4)]

#print(ip_origen_check)
#print(ip_destino_check)

#Unir las listas con los componentes para el checkusum del header
checksumList1= checksumList1+ip_origen_check+ip_destino_check

i=0
for _ in checksumList1:
    checksumList1[i]="0x"+checksumList1[i]
    i+=1


#print(checksumList1)

#Calcular el checkusum del header
header_checkshum=0
for i in range(0,len(checksumList1)):
    header_checkshum = int(checksumList1[i],16)+header_checkshum


#Negación con 0xffff
while header_checkshum > int('0xffff', 16):
    header_checkshum = header_checkshum - int('0xffff', 16)

header_checkshum = int('0xffff', 16) - header_checkshum
    

header_checkshum=hex(header_checkshum)

print("\nHeader Checksum: "+header_checkshum)

header_checkshum=header_checkshum[2:]



#Crear última Fila header con Checksum
ip_header_row3 = [header_checkshum[i:i+2] for i in range(0, len(header_checkshum), 2)]

i=0
for _ in ip_header_row3:
    ip_header_row3[i]="0x"+ ip_header_row3[i]
    i+=1

ip_header_row3 = ip_header_row3_minuscheck+ip_header_row3


#Armar IP Header
ip_header  = bytes([int(x,16) for x in ip_header_row1])  # Version, IHL, Type of Service | Total Length
ip_header += bytes([int(x,16) for x in ip_header_row2])  # Identification | Flags, Fragment Offset
ip_header += bytes([int(x,16) for x in ip_header_row3])  # TTL, Protocol | Header Checksum
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

#print(ip_origen_check)
#print(ip_destino_check)


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
    

tcp_checkshum=hex(tcp_checkshum)
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


