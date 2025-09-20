# Protecto---Password-Manager
A Password Vault for storage of passwords and to generator strong and safe passwords

    
File required to be download for the program to run normally --
    
    
    pip install cryptography
    pip install pyperclip
    pip install customTkinter
    pip install pyinstaller

To run ---

    **Download zip-file and extract it or clone the repository and Open it in a Compiler**

    Open the program named "Double Trouble.py" and run the programs
    

Content --

    The folder contains 
    =>Double Trouble.py
        The code used to run the two programs
   
    =>Protecto.py
        The code used to make the vault for the storage of the password
            The vault contains three different screens
             - firstScreen = this screen is for     
               the creation of the Master code
            
             - loginScreen = this screen is for
               Main login screen ,which will occur only
               after the master code is created
             
             - passwordVault = this screen is the 
               storage vault for all your important passwords
    
    =>Protecto Password Generator
        This program is used for generating the password by just inputting the total number of characters you would want for your password
    
    =>Protecto.db
        This is the database file where all the table are stored.
        The database program I have used is sqlite3

        (#incase the creat master password screen doesnt occur that means the database isnt empty
        Either clear the database or delete it and create another database with the name "Protecto.db" )

    =>Resources (file)
        This file contains the images for the background of the screens and the icon of the screen 
        #changing to your custom image
            In the file Protecto.py search for the file name (shortcut => crl + f or crl + h) icon and change the destination of the file to your choice

        #changing to your custom icon
            In the file Protecto.py search for the file name (shortcut => crl + f or crl + h) bg_image and change the destination 
            of the file to your choice 
This code wouldn't be able to come to reality without the help of various different people and sites from which Ive taken much inspiration from . I used their codes as reference to bring this program to what it is now.

Reference


#https://github.com/collinsmc23/python-sql-password-manager.git

#https://www.youtube.com/@raxocoding9298

#https://www.youtube.com/@Codemycom

#https://stackoverflow.com/

#https://customtkinter.tomschimansky.com


(Various other sources were used for beautifying and correcting small mistakes in the code)




