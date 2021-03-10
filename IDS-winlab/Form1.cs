using System;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using NdisApiDotNet;


namespace IDS_winlab
{
	public partial class Form1 : Form
	{
		public Form1()
		{
			InitializeComponent();
		}

		private void button1_Click(object sender, EventArgs e)
		{
			string textbox3 = textBox3.Text;
			var filter = NdisApi.Open();
			if (!filter.IsValid)
				textBox1.Text = "Драйвер не найден";
			textBox1.Text = $"{filter.GetVersion()}";
			//Создать и установить событие для адаптеров
			var waitHandlesCollection = new List<ManualResetEvent>();
			// Создание списка сетевых адаптеров
			var tcpAdapters = new List<NetworkAdapter>();
			foreach (var networkAdapter in filter.GetNetworkAdapters())
			{
				if (networkAdapter.IsValid)
				{
					var success = filter.SetAdapterMode(networkAdapter,
					NdisApiDotNet.Native.NdisApi.MSTCP_FLAGS.MSTCP_FLAG_TUNNEL |
					NdisApiDotNet.Native.NdisApi.MSTCP_FLAGS.MSTCP_FLAG_LOOPBACK_FILTER |
					NdisApiDotNet.Native.NdisApi.MSTCP_FLAGS.MSTCP_FLAG_LOOPBACK_BLOCK);
					var manualResetEvent = new ManualResetEvent(false);
					success &= filter.SetPacketEvent(networkAdapter, manualResetEvent.SafeWaitHandle);
					if (success)
					{
						textBox2.Text = textBox2.Text + $"Добавлен адаптер: {networkAdapter.FriendlyName}\r\n";
						// Добавление адаптеров в список
						waitHandlesCollection.Add(manualResetEvent);
						tcpAdapters.Add(networkAdapter);
					}
				}
			}
			var waitHandlesManualResetEvents = waitHandlesCollection.Cast<ManualResetEvent>().ToArray();
			var waitHandles = waitHandlesCollection.Cast<WaitHandle>().ToArray();
			textBox3.Text = "===== Запуск анализа пакетов =====\r\n";

			IDS ids = new IDS();
			Thread ThreadIDS = new Thread((ThreadStart)delegate { ids.SYNFloodDetector(filter, waitHandles, tcpAdapters.ToArray(), waitHandlesManualResetEvents, this); });
			ThreadIDS.IsBackground = true;
			ThreadIDS.Start();
		}

		private void button2_Click(object sender, EventArgs e)
		{
			this.Close();
		}

		public void UpdateTxt(string str)
		{
			if (InvokeRequired)
			{

				this.Invoke(new Action<string>(UpdateTxt), new object[] { str });
				return;
			}
			textBox3.AppendText(str);
		}
	}
}