using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CourceProjectCryptography.ViewModel
{
    internal class BaseViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        protected void OnPropertiesChanged(params string[] propertiesNames)
        {
            foreach (var propertyName in propertiesNames)
            {
                OnPropertyChanged(propertyName);
            }
        }
    }
}
