package kerberos;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class Kerberos {
    private static final int PORT = 20005;
    private static final int NM = 10;
    ServerSocket server;
    Socket connect[];
    ArrayList<Character> alf,hashalf;
    private ArrayList<String> user=null;
    private ArrayList<String> pass=null;
    private ArrayList<String> services_ids=null;
    private ArrayList<String> services_psws=null;

    public Kerberos(){
        int i=0;
        generate_hash();
        String[][] user_data = getInfoAtTXT("users.txt");
        user = new ArrayList<>(Arrays.asList(user_data[0]));
        pass = new ArrayList<>(Arrays.asList(user_data[1]));
        String[][] services_data = getInfoAtTXT("services.txt");
        services_ids = new ArrayList<>(Arrays.asList(services_data[0]));
        services_psws = new ArrayList<>(Arrays.asList(services_data[1]));        

        try {    
            connect = new Socket[NM];
            server= new ServerSocket(PORT);
            System.out.println("Esperando por clientes.");
            thread hilo[]= new thread[NM];
            while(i<NM){
                connect[i]=server.accept();
                System.out.println("Conectado cliente "+connect[i].getInetAddress());
                hilo[i]=new thread(connect[i]);
                hilo[i].start();
                i++;
            }
        } catch (IOException ex) {
            Logger.getLogger(Kerberos.class.getName()).log(Level.SEVERE, null, ex);
        }
    }       
    
    private String[][] getInfoAtTXT(String FILENAME){
        BufferedReader br = null;
        FileReader fr = null;
        int line = 0;
        String users[] = null;
        String psw[] = null;
        try {
                fr = new FileReader(FILENAME);
                br = new BufferedReader(fr);
                String sCurrentLine;
                System.out.println(br);
                while ((sCurrentLine = br.readLine()) != null) {
                        line++;
                        if(line == 1)
                            users = sCurrentLine.split(" ");
                        else
                            psw = sCurrentLine.split(" ");
                        //System.out.println(sCurrentLine);
                }

        } catch (IOException e) {
                e.printStackTrace();
        } finally {
                try {
                        if (br != null)
                                br.close();

                        if (fr != null)
                                fr.close();
                } catch (IOException ex) {
                        ex.printStackTrace();
                }
        }
        String[][] data = {users, psw};
        return data;
    }
    
    class thread extends Thread{
        Socket _socket; 
        DataInputStream in;
        DataOutputStream out;
        thread(Socket sockaux){
            try {
                _socket=sockaux;
                in=new DataInputStream(_socket.getInputStream());
                out= new DataOutputStream(_socket.getOutputStream());
            } catch (IOException ex) {
                Logger.getLogger(Kerberos.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        @Override
        public void run(){
            int usernumber = 0, servicenumber = 0;
            try {
                String message= in.readUTF();
                System.out.println(message);
                //Separar con un espacio el nombre del usuario y el ID
                //Revisar que el ID del servicio exista
                //Igual que como se verifica el nombre del usuario
                String[] message_sep = message.split(" ");
                String[] data_sol = null;
                usernumber = verify_user(message_sep[0]);
                servicenumber = verify_service(message_sep[1]);
                if(usernumber!=-1 && servicenumber != -1){
                    System.out.println("----AS----");
                    //Se hace el hash de la clave del servicio (codepass) y se encripta con la clave del usuario
                    message=encrypt(codePass(services_psws.get(servicenumber)),pass.get(usernumber));
                    System.out.println("Se envía clave de servicio encriptado con clave del usuario " + user.get(usernumber) + ": " + message);
                    out.writeUTF(message);
                    //Se genera el tiempo de válidez de 1 a 60 segundos
                    Integer valid_time = (int) (Math.random() * 60) + 1;
                    //Se encripta el tiempo de validez con la contraseña del usuario
                    message=encrypt(codePass(valid_time.toString()),pass.get(usernumber));
                    System.out.println("Se envía tiempo de validez de servicio encriptado con clave del usuario " + user.get(usernumber) + ": " + message);
                    out.writeUTF(message);
                    System.out.println("-----SS-----");
                    //A partir de aqui sería el SS
                    //ahora el SS espera recibir la solicitud del servicio, 
                    //El SS recibe el nombre, servicio y contraseña de servicio encriptada con contraseña del usuario
                    //Debe recibir todo porque se supone que se simula un servidor aparte
                    message = in.readUTF();
                    data_sol = message.split(" ");
                    System.out.println("SS Recibiendo solicitud del usuario " + data_sol[0] + " del servicio " + data_sol[1] + ": " + message);
                    int usernumberss = verify_user(data_sol[0]);
                    int servicenumberss = verify_service(data_sol[1]);
                    if(usernumber!=-1 && servicenumber != -1){
                        String ser_pass = desencrypt(data_sol[2], pass.get(usernumberss));
                        ser_pass = decodePass(ser_pass);
                        System.out.println(ser_pass);
                        if(ser_pass.compareTo(services_psws.get(servicenumberss)) == 0){
                            System.out.println("El usuario se ha logeado en el servicio");
                            out.writeUTF("OK prestando servicio de " + data_sol[1] + " por " + valid_time.toString() + "s");
                        }else{
                            System.out.println("Error, contraseñas no coinciden");
                            _socket.close();    
                        }
                            
                    }else{
                        System.out.println("SS ha recibido servicio o usuario erróneo");
                        _socket.close();
                    }

                    
                    
                    
                    
                    
                    /*
                    message=encrypt(codePass(passTGSpub),pass.get(usernumber));
                    out.writeUTF(message);
                    System.out.println("Se envio el mensaje con la clave publica del TGS, encriptado asi: "+message);
                    message=user.get(usernumber)+","+_socket.getInetAddress()+","+passTGSpub;
                    message=encrypt(codePass(message),passTGSpri);
                    out.writeUTF(message);
                    System.out.println("Se envio el ticket cifrado con la clave privada del TGS, encriptado asi: "+message);
                    message=in.readUTF();
                    System.out.println("El cliente envia: "+message);
                    message=desencrypt(message, passTGSpri);
                    System.out.println("Desencriptando con la clave privada del TGS: "+message);
                    message=decodePass(message);
                    System.out.println("Decodificando: "+message);
                    String aux[]=message.split(",");
                    message=in.readUTF();
                    message=desencrypt(message, passTGSpub);
                    message=decodePass(message);
                    if(message.compareTo(aux[0])==0 && aux[2].compareTo(passTGSpub)==0){
                        System.out.println("Ticket valido.");
                        String auxs="";
                        for (int i = 0; i < aux[0].length() && i < passTGSpub.length(); i++) {
                            auxs+=aux[0].charAt(i);
                            auxs+=passTGSpub.charAt(i);
                        }
                        message=encrypt(codePass(auxs), passTGSpub);
                        System.out.println("Clave cliente/servidor generada: "+auxs+". Se encripto: "+message);
                        out.writeUTF(message);
                        message=user.get(usernumber)+","+_socket.getInetAddress()+","+auxs;
                        message=encrypt(codePass(message),passSSpri);
                        out.writeUTF(message);
                        System.out.println("Se envia el ticket para autenticarse frente al SS encriptado: "+message);
                        message=in.readUTF();
                        System.out.println("El cliente envia: "+message);
                        message=desencrypt(message, passSSpri);
                        System.out.println("Desencriptando con la clave privada del SS: "+message);
                        message=decodePass(message);
                        System.out.println("Decodificando: "+message);
                        aux=message.split(",");
                        message=in.readUTF();
                        message=desencrypt(message, auxs);
                        message=decodePass(message);
                        if(message.compareTo(aux[0])==0 && aux[2].compareTo(auxs)==0){
                            System.out.println("Ticket SS valido");
                            message=encrypt(codePass("Soy el SS y te estoy prestando el servicio."), auxs);
                            out.writeUTF(message);
                            System.out.println("Se esta prestando el servicio.");
                        }else{
                            System.out.println("Ticket no valido.");
                            _socket.close();
                        }
                    }else{
                        System.out.println("Ticket no valido.");
                        _socket.close();
                    }*/
                }else{
                    System.out.println("Usuario o servicio no válido: "+message + ". Se rechazo la solicitud");
                    _socket.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(Kerberos.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private int verify_user(String nombre) {
        for (int i = 0; i < user.size(); i++)
                    if(nombre.compareTo(user.get(i))==0){
                        System.out.println("Usuario válido: "+nombre);
                        return i;
                    }
        return -1;
    }

    private int verify_service(String nombre) {
        for (int i = 0; i < services_ids.size(); i++)
                    if(nombre.compareTo(services_ids.get(i))==0){
                        System.out.println("Servicio válido: "+nombre);
                        return i;
                    }
        return -1;
    }
    
    private String encrypt(String message, String pass){
        int aux=0;String enc="";
        //Se recorre cada caracter de la contraseña y se suma el valor numerico del char
        for (int i = 0; i < pass.length(); i++) 
            aux+=pass.codePointAt(i);
        //
        aux/=100;
        for (int i = 0; i < message.length(); i++){
            int c=message.charAt(i);
            enc+=(char)(c + aux);
        }
        return enc;
    }
    
    private String desencrypt(String codePass,String passUser){
        int aux=0;String enc="";
        for (int i = 0; i < passUser.length(); i++) 
            aux+=passUser.codePointAt(i);
        aux/=100;
        for (int i = 0; i < codePass.length(); i++){
            int c=codePass.charAt(i);
            enc+=(char)(c - aux);
        }
        return enc;
    }
    
    private String codePass(String pass) {
        String hash="";
        for (int i = 0; i < pass.length(); i++) {
            char c=pass.charAt(i);
            for (int j = 0; j < alf.size(); j++) 
                if(alf.get(j).compareTo(c)==0){
                    hash+=hashalf.get(j);
                    break;
                }
        }
        System.out.println("El mensaje es: " +pass+". Se codifico a: "+hash);
        return hash;
    }
    
    private String decodePass(String pass) {
        String hash="";
        for (int i = 0; i < pass.length(); i++) {
            char c=pass.charAt(i);
            for (int j = 0; j < alf.size(); j++) 
                if(hashalf.get(j).compareTo(c)==0){
                    hash+=alf.get(j);
                    break;
                }
        }
        System.out.println("El mensaje es: " +pass+". Se decodifico a: "+hash);
        return hash;
    }
    
    private void generate_hash() { 
        FileWriter fichero = null;
        PrintWriter pw = null;
        
        alf = new ArrayList<>();
        hashalf = new ArrayList<>();
        for (int i = 33; i < 126; i++)
            alf.add((char) i);
        FileReader fr = null;
        try {
            hashalf = new ArrayList<>();
            File archivo = new File ("hash.txt");
            fr = new FileReader (archivo);
            BufferedReader br = new BufferedReader(fr);
            String linea;
            while((linea=br.readLine())!=null){
                for (int i = 0; i < linea.length(); i++) 
                    hashalf.add(linea.charAt(i));
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Kerberos.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Kerberos.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fr.close();
            } catch (IOException ex) {
                Logger.getLogger(Kerberos.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    public static void main(String[] args) {
        Kerberos k =new Kerberos();
    }
}
