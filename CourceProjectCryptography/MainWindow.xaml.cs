using CourceProjectCryptography.ViewModel;

namespace CourceProjectCryptography
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow
	{
		public MainWindow()
		{
            DataContext = new MainViewModel();
			InitializeComponent();
		}
	}
}