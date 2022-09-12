using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using СryptographyAlg;
using FTPMethods;
using Microsoft.Win32;
using System.IO;
using System.Windows.Controls;

namespace CourceProjectCryptography.ViewModel
{
    class MainViewModel : BaseViewModel
    {
        private LUC luc = new LUC();
        private FTP ftp = new FTP();
        private CryptMode cryptMode = new CryptMode();
        private bool _ecb = true;
        private bool _cbc;
        private bool _ofb;
        private bool _cfb;
        private string _publicKey;
        private string _iv;
        private ICommand _generateInitVecCommand;
        private ICommand _sendInitVecCommand;
        private ICommand _getInitVecCommand;
        private ICommand _generateAsymmetricKeyCommand;
        private ICommand _sendPublicKeyCommand;
        private ICommand _getPublicKeyCommand;
        private ICommand _generateSessionKeyCommand;
        private ICommand _sendSessionKeyCommand;
        private ICommand _getSessionKeyCommand;
        private ICommand _sendFileCommand;
        private ICommand _getFileCommand;
        private ICommand _encryptCommand;
        private ICommand _decryptCommand;

        public ICommand GenerateAsymmetricKeyCommand =>
           _generateAsymmetricKeyCommand ?? (_generateAsymmetricKeyCommand = new RelayCommand(async _ => await GenerateAsymmetricKey()));
        public ICommand SendPublicKeyCommand =>
            _sendPublicKeyCommand ?? (_sendPublicKeyCommand = new RelayCommand(async _ => await SendPublicKey()));
        public ICommand GetPublicKeyCommand =>
            _getPublicKeyCommand ?? (_getPublicKeyCommand = new RelayCommand(async _ => await GetPublicKey()));
        public ICommand GenerateSessionKeyCommand =>
            _generateSessionKeyCommand ?? (_generateSessionKeyCommand = new RelayCommand(async _ => await GenerateSessionKey()));
        public ICommand SendSessionKeyCommand =>
            _sendSessionKeyCommand ?? (_sendSessionKeyCommand = new RelayCommand(async _ => await SendSessionKey()));
        public ICommand GetSessionKeyCommand =>
            _getSessionKeyCommand ?? (_getSessionKeyCommand = new RelayCommand(async _ => await GetSessionKey()));
        public ICommand GenerateInitVecCommand =>
            _generateInitVecCommand ?? (_generateInitVecCommand = new RelayCommand(async _ => await GenerateInitVec()));
        public ICommand SendInitVecCommand =>
            _sendInitVecCommand ?? (_sendInitVecCommand = new RelayCommand(async _ => await SendInitVec()));
        public ICommand GetInitVecCommand =>
            _getInitVecCommand ?? (_getInitVecCommand = new RelayCommand(async _ => await GetInitVec()));
        public ICommand SendFileCommand =>
            _sendFileCommand ?? (_sendFileCommand = new RelayCommand(async _ => await SendFile()));
        public ICommand GetFileCommand =>
            _getFileCommand ?? (_getFileCommand = new RelayCommand(async _ => await GetFile()));
        public ICommand EncryptCommand =>
            _encryptCommand ?? (_encryptCommand = new RelayCommand(async _ => await Encrypt()));
        public ICommand DecryptCommand =>
            _decryptCommand ?? (_decryptCommand = new RelayCommand(async _ => await Decrypt()));

        public bool ECB
        {
            get => _ecb;
            set
            {
                _ecb = value;
                if (value)
                {
                    CBC = false;
                    OFB = false;
                    CFB = false;
                    cryptMode.encryptionMode = EncryptionModeEnum.ECB;
                }
                OnPropertyChanged(nameof(ECB));
            }
        }
        public bool CBC
        {
            get => _cbc;
            set
            {
                _cbc = value;
                if (value)
                {
                    ECB = false;
                    OFB = false;
                    CFB = false;
                    cryptMode.encryptionMode = EncryptionModeEnum.CBC;
                }
                OnPropertyChanged(nameof(CBC));
            }
        }
        public bool OFB
        {
            get => _ofb;
            set
            {
                _ofb = value;
                
                if (value)
                {
                    ECB = false;
                    CBC = false;
                    CFB = false;
                    cryptMode.encryptionMode = EncryptionModeEnum.OFB;
                }
                OnPropertyChanged(nameof(OFB));
            }
        }
        public bool CFB
        {
            get => _cfb;
            set
            {
                _cfb = value;
                if (value)
                {
                    ECB = false;
                    CBC = false;
                    OFB = false;
                    cryptMode.encryptionMode = EncryptionModeEnum.CFB;
                }
                OnPropertyChanged(nameof(CFB));
            }
        }

        public string PublicKey
        {
            get => _publicKey;
            set
            {
                _publicKey = value;
                OnPropertyChanged(nameof(PublicKey));
            }
        }

        public string IV
        {
            get => _iv;
            set
            {
                _iv = value;
                OnPropertyChanged(nameof(IV));
            }
        }
        async Task Encrypt()
        {
            if (cryptMode.shacal.Key == null)
            {
                MessageBox.Show("Отсутсвует сеансовый ключ");
                return;
            }
            if (cryptMode.encryptionMode != EncryptionModeEnum.ECB && cryptMode.IV == null)
            {
                MessageBox.Show("Для этого режима шифрования необходим IV");
                return;
            }
            string inputFile;
            if ((inputFile = OpenFile()) == null)
                return;

            string outputFile;
            if ((outputFile = SaveFile("enc_" + inputFile.Split('\\').Last())) == null)
                return;
            
            Task encrypt = Task.Run(() =>
                {
                    cryptMode.EncryptFile(inputFile, outputFile);
                }
            );
            await encrypt;
            
            MessageBox.Show(String.Format("Файл {0} успешно зашифрован", outputFile.Split('\\').Last()));

        }

        async Task Decrypt()
        {
            if (cryptMode.shacal.Key == null)
            {
                MessageBox.Show("Отсутсвует сеансовый ключ");
                return;
            }
            if (cryptMode.encryptionMode != EncryptionModeEnum.ECB && cryptMode.IV == null)
            {
                MessageBox.Show("Для этого режима шифрования необходим IV");
                return;
            }
            string inputFile;
            if ((inputFile = OpenFile()) == null)
                return;

            string outputFile;
            if ((outputFile = SaveFile("dec_" + inputFile.Split('\\').Last())) == null)
                return;
            Task decrypt = Task.Run(() =>
                {
                    cryptMode.DecryptFile(inputFile, outputFile);
                }
            );
            await decrypt;
            
            MessageBox.Show(String.Format("Файл {0} успешно расшифрован", outputFile.Split('\\').Last()));
        }

        #region File
        private string OpenFile()
        {
            string filename = null;
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                filename = openFileDialog.FileName;
            }
            return filename;
        }

        private string SaveFile(string _fileName="")
        {
            string filename = null;
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.FileName = _fileName;
            if (saveFileDialog.ShowDialog() == true)
            {
                filename = saveFileDialog.FileName;
            }
            return filename;
        }

        async Task SendFile()
        {
            string inputFile;
            if ((inputFile = OpenFile()) == null)
                return;
            Task sendFile = Task.Run(() =>
            {
                try
                {
                    ftp.SendFile(inputFile, "EncryptedFile.txt");
                } catch(Exception)
                {
                    MessageBox.Show("Проблемы с соединением");
                    return;
                }
                
                MessageBox.Show("Файл отправлен на сервер");
            }
            );

            await sendFile;
        }

        async Task GetFile()
        {
            string outputFile;
            if ((outputFile = SaveFile()) == null)
                return;
            Task getFile = Task.Run(() =>
            {
                try {
                    ftp.GetFile(outputFile, "EncryptedFile.txt");
                } catch (Exception)
                {
                    MessageBox.Show("Проблемы с соединением");
                    return;
                }
            MessageBox.Show("Файл скачен");
            });
            await getFile;
        }
        #endregion

        #region AsymmetricKey
        async Task GenerateAsymmetricKey()
        {
            Task generateKey = Task.Run(() =>
                {
                    luc.GenerateKey();
                    PublicKey = String.Format("Сгенерирован\n" +
                        "e: {0}\n" +
                        "n: {1}", luc.PublicKey.FirstValue.ToString(), luc.PublicKey.SecondValue.ToString());
                    MessageBox.Show("Ключ успешно сгенерирован");
                }
            );

            await generateKey;
            
        }

        async Task SendPublicKey()
        {
            if (!luc.isPublicKey())
            {
                MessageBox.Show("Публичный ключ отсутствует!!!");
                return;
            }

            Task sendKey = Task.Run(() =>
                {
                    try
                    {
                        ftp.SendPublicKey("publicKey.txt", luc.PublicKey);
                    }
                    catch (Exception)
                    {
                        MessageBox.Show("Проблемы с соединением");
                        return;
                    }
                    MessageBox.Show("Публичный ключ выложен");
                }
            );

            await sendKey;
        }

        async Task GetPublicKey()
        {
            Task getKey = Task.Run(() =>
            {
                try
                {
                    var answer = ftp.GetPublicKey("publicKey.txt");
                    luc.PublicKey = answer.Item2;
                    PublicKey = String.Format("Получен\n" +
                        "e: {0}\n" +
                        "n: {1}", luc.PublicKey.FirstValue.ToString(), luc.PublicKey.SecondValue.ToString());
                }
                catch (Exception)
                {
                    MessageBox.Show("Проблемы с соединением");
                    return;
                }
                MessageBox.Show("Публичный ключ скачен");
            }
            );

            await getKey;
        }

        #endregion

        #region SessionKey
        async Task GenerateSessionKey()
        {
            Task generateKey = Task.Run(() =>
            {
                cryptMode.shacal.GenerateKey();
                MessageBox.Show(String.Format("Сеансовый ключ сгенерирован: {0}", BitConverter.ToString(cryptMode.shacal.Key).Replace("-", "")));
            });

            await generateKey;
        }

        async Task SendSessionKey()
        {
            if (!luc.isPublicKey())
            {
                MessageBox.Show("Публичный ключ отсутствует!!!");
                return;
            }

           if(cryptMode.shacal.Key == null)
            {
                MessageBox.Show("Сеансовый ключ отсутствует!!!");
                return;
            }
            Task sendKey = Task.Run(() =>
            {
                try
                {
                    ftp.SendArrayByte("SessionKey.txt", luc.Encrypt(cryptMode.shacal.Key));
                }
                catch (Exception)
                {
                    MessageBox.Show("Проблемы с соединением");
                    return;
                }
                MessageBox.Show("Сеансовый ключ выложен");
            }
            );

            await sendKey;
            
        }

        async Task GetSessionKey()
        {
            if (!luc.isPublicKey())
            {
                MessageBox.Show("Приватный ключ отсутствует!!!");
                return;
            }
            Task getKey = Task.Run(() =>
            {
                try
                {
                    var answer = ftp.GetArrayByte("SessionKey.txt");
                    cryptMode.shacal.Key = luc.Decrypt(answer.Item2);
                }
                catch (Exception)
                {
                    MessageBox.Show("Проблемы с соединением");
                    return;
                }
                MessageBox.Show("Сеансовый ключ скачан");
            }
            );

            await getKey;
        }
        #endregion

        #region InitVec
        async Task GenerateInitVec()
        {
            Task generateKey = Task.Run(() =>
            {
                cryptMode.GenerateIV();
                MessageBox.Show("IV сгенерирован успешно");
                IV = BitConverter.ToString(cryptMode.IV).Replace("-", "");
            });

            await generateKey;
           
        }

        async Task SendInitVec()
        {
            if (!luc.isPublicKey())
            {
                MessageBox.Show("Публичный ключ отсутствует!!!");
                return;
            }
            if (cryptMode.IV == null)
            {
                MessageBox.Show("IV отсутствует!!!");
                return;
            }

            Task sendKey = Task.Run(() =>
                {
                    try
                    {
                        ftp.SendArrayByte("IV.txt", luc.Encrypt(cryptMode.IV));
                    }
                    catch (Exception)
                    {
                        MessageBox.Show("Проблемы с соединением");
                        return;
                    }
                    MessageBox.Show("IV выложен");
                }
            );

            await sendKey;
            
        }

        async Task GetInitVec()
        {
            if (!luc.isPublicKey())
            {
                MessageBox.Show("Приватный ключ отсутствует!!!");
                return;
            }
            Task getKey = Task.Run(() =>
            {
                try
                {
                    var answer = ftp.GetArrayByte("IV.txt");
                    cryptMode.IV = luc.Decrypt(answer.Item2);
                    
                }
                catch (Exception)
                {
                    MessageBox.Show("Проблемы с соединением");
                    return;
                }
                MessageBox.Show("IV скачан");
                IV = BitConverter.ToString(cryptMode.IV).Replace("-", "");
            }
            );

            await getKey;
        }
        #endregion
    }
}
