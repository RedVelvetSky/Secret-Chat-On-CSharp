   M S B A M L   `   `   `  ����  
SecretChat    SecretChat.MainWindow   5   	   W SPresentationCore, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   R NSystem.Xaml, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	     � Title$  Simple Secure Chat��5   	   $	��450��6$   $	��800��61   $	��700��5   	   $	��300��6   .��5	      � ���#222 � RowDefinitions 5
   
   �� 5      $��40 �6   �� 5      �� 5      $
��Auto �6   .+�5   
   �� $��0��6    �� Orientation$ 
Horizontal=�6"   $��Center=�6;   $��5q�6X   .+�5      �� $��Your ID:��6   
�������6'   �� 5      -   5         ��Name$ ClientIdTextBox��5      $	��100��6/   $��5q�6;   $��1q�6F   ���#444���#222
�������6   �� 5      $��Recipient ID:��6   
�������6,   �� 5      -   5        $ RecipientIdTextBox��5      $	��100��62   $��5q�6>   $��1q�6I   ���#444���#222
�������6�   �� 5      -   5         ��Name$ ConnectButton��5      $��Connect��6,   $��5q�6Z   $��1q�6e   ���#444���#007ACC
�������6�   �� 5      -   5        $ DisconnectButton��5      $��
Disconnect��6/   $��5q�6c   ${�False��6n   $��1q�6�   ���#444
���  ��
���   �6�   5      �� 5   
   -   5        $ ChatTextBox��5      $��1��6'    �� 
IsReadOnly$
 True��64    �� TextWrapping$
 Wrap=�6F   " �� VerticalScrollBarVisibility$
 Auto=�6Z    �� AcceptsReturn$
 True��6}   $��5q�6�   $��1q�6�   ���#444���#222
�������6�   �� 5   
   $��2��6   $ 
Horizontal=�6"   $��Center=�6;   $��5q�6X   .+�5      �� -   5        $ MessageTextBox��5      $	��600��6.   $��5q�6:   $��1q�6E   ���#444���#222
�������6~   �� 5      -   5        $ SendMessageButton��5      $
��Send��60   $��5q�6_   ${�False��6j   $��1q�6|   ���#444���#007ACC
���   �6�   5      5      5       