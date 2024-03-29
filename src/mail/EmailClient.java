/**
 * 
 */
package mail;

/**
 * @author lardnerl
 * Taken from http://www.java-tips.org/java-se-tips/javax.swing/how-to-create-an-e-mail-client-in-java.htm
 */
import java.awt.*;
import java.awt.event.*;
import java.util.*;

import javax.mail.*;
import javax.mail.internet.*;
import javax.swing.*;
import javax.swing.event.*;

//The E-mail Client.
public class EmailClient extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4854259004870688326L;

	// Message table's data model.
	private MessagesTableModel tableModel;

	// Table listing messages.
	private JTable table;

	// This the text area for displaying messages.
	private JTextArea messageTextArea;

	/*
	 * This is the split panel that holds the messages table and the message
	 * view panel.
	 */
	private JSplitPane splitPane;

	// These are the buttons for managing the selected message.
	private JButton replyButton, forwardButton, deleteButton;

	// Currently selected message in table.
	private Message selectedMessage;

	// Flag for whether or not a message is being deleted.
	private boolean deleting;

	// This is the JavaMail session.
	private Session session;

	private String userName, passWord;

	// Constructor for E-mail Client.
	public EmailClient() {
		// Set application title.
		setTitle("E-mail Client");

		// Set window size.
		setSize(640, 480);

		// Handle window closing events.
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				actionExit();
			}
		});

		// Setup file menu.
		JMenuBar menuBar = new JMenuBar();
		JMenu fileMenu = new JMenu("File");
		fileMenu.setMnemonic(KeyEvent.VK_F);
		JMenuItem fileExitMenuItem = new JMenuItem("Exit", KeyEvent.VK_X);
		fileExitMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				actionExit();
			}
		});
		fileMenu.add(fileExitMenuItem);
		menuBar.add(fileMenu);
		setJMenuBar(menuBar);

		// Setup buttons panel.
		JPanel buttonPanel = new JPanel();
		JButton newButton = new JButton("New Message");
		newButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				actionNew();
			}
		});


		// Setup messages table.
		tableModel = new MessagesTableModel();
		table = new JTable(tableModel);
		table.getSelectionModel().addListSelectionListener(
				new ListSelectionListener() {
					public void valueChanged(ListSelectionEvent e) {
						tableSelectionChanged();
					}
				});
		// Allow only one row at a time to be selected.
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		// Setup E-mails panel.
		JPanel emailsPanel = new JPanel();
		emailsPanel.setBorder(BorderFactory.createTitledBorder("E-mails"));
		messageTextArea = new JTextArea();
		messageTextArea.setEditable(false);
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(
				table), new JScrollPane(messageTextArea));
		emailsPanel.setLayout(new BorderLayout());
		emailsPanel.add(splitPane, BorderLayout.CENTER);

		// Setup buttons panel 2.
		JPanel buttonPanel2 = new JPanel();
		replyButton = new JButton("Reply");
		replyButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				actionReply();
			}
		});
		replyButton.setEnabled(false);
		buttonPanel2.add(replyButton);
		forwardButton = new JButton("Forward");
		forwardButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				actionForward();
			}
		});
		forwardButton.setEnabled(false);
		buttonPanel2.add(forwardButton);
		deleteButton = new JButton("Delete");
		deleteButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				actionDelete();
			}
		});
		deleteButton.setEnabled(false);
		buttonPanel2.add(deleteButton);

		// Add panels to display.
		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(buttonPanel, BorderLayout.NORTH);
		getContentPane().add(emailsPanel, BorderLayout.CENTER);
		getContentPane().add(buttonPanel2, BorderLayout.SOUTH);
	}

	// Exit this program.
	private void actionExit() {
		System.exit(0);
	}

	// Create a new message.
	private void actionNew() {
		sendMessage(MessageDialog.NEW, null);
	}

	// Called when table row selection changes.
	private void tableSelectionChanged() {
		/*
		 * If not in the middle of deleting a message, set the selected message
		 * and display it.
		 */
		if (!deleting) {
			selectedMessage = tableModel.getMessage(table.getSelectedRow());
			showSelectedMessage();
			updateButtons();
		}
	}

	// Reply to a message.
	private void actionReply() {
		sendMessage(MessageDialog.REPLY, selectedMessage);
	}

	// Forward a message.
	private void actionForward() {
		sendMessage(MessageDialog.FORWARD, selectedMessage);
	}

	// Delete the selected message.
	private void actionDelete() {
		deleting = true;

		try {
			// Delete message from server.
			selectedMessage.setFlag(Flags.Flag.DELETED, true);
			Folder folder = selectedMessage.getFolder();
			folder.close(true);
			folder.open(Folder.READ_WRITE);
		} catch (Exception e) {
			showError("Unable to delete message.", false);
		}

		// Delete message from table.
		tableModel.deleteMessage(table.getSelectedRow());

		// Update GUI.
		messageTextArea.setText("");
		deleting = false;
		selectedMessage = null;
		updateButtons();
	}

	// Send the specified message.
	private void sendMessage(int type, Message message) {
		// Display message dialog to get message values.
		MessageDialog dialog;
		try {
			dialog = new MessageDialog(this, type, message);
			if (!dialog.display()) {
				// Return if dialog was cancelled.
				return;
			}
		} catch (Exception e) {
			showError("Unable to send message.", false);
			return;
		}

		try {
			// Create a new message with values from dialog.
			Message newMessage = new MimeMessage(session);
			/*Encrypt and sign message*/
			newMessage = Encryption.toEncrypt(dialog.getSubject(),
					dialog.getContent(), dialog.getFrom(), dialog.getTo(),
					session);
			newMessage.setSentDate(new Date());
			// Send new message.
			Transport.send(newMessage);

		} catch (Exception e) {
			e.printStackTrace();
			showError("Unable to send message.", false);
		}
	}

	// Show the selected message in the content panel.
	private void showSelectedMessage() {
		// Show hour glass cursor while message is loaded.
		setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		try {
			/* if message content is of type encrypted, decrypt, verify signature and show. Else just show*/
			if (selectedMessage.getContentType().contains(
					"APPLICATION/PKCS7-MIME;"))
				messageTextArea.setText(Encryption.toDecrypt(selectedMessage,
						session));
			else
				messageTextArea.setText(getMessageContent(selectedMessage));
			messageTextArea.setCaretPosition(0);
		} catch (Exception e) {
			showError("Unabled to load message.", false);
		} finally {
			// Return to default cursor.
			setCursor(Cursor.getDefaultCursor());
		}
	}

	/*
	 * Update each button's state based off of whether or not there is a message
	 * currently selected in the table.
	 */
	private void updateButtons() {
		if (selectedMessage != null) {
			replyButton.setEnabled(true);
			forwardButton.setEnabled(true);
			deleteButton.setEnabled(true);
		} else {
			replyButton.setEnabled(false);
			forwardButton.setEnabled(false);
			deleteButton.setEnabled(false);
		}
	}

	// Show the application window on the screen.
	@SuppressWarnings("deprecation")
	public void show() {
		super.show();

		// Update the split panel to be divided 50/50.
		splitPane.setDividerLocation(.5);
	}

	// Connect to e-mail server.
	public void connect() {
		// Display connect dialog.
		ConnectDialog dialog = new ConnectDialog(this);
		dialog.setVisible(true);

		// Build connection URL from connect dialog settings.

		/*
		 * Display dialog stating that messages are currently being downloaded
		 * from server.
		 */
		final DownloadingDialog downloadingDialog = new DownloadingDialog(this);
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				downloadingDialog.setVisible(true);
			}
		});

		// Establish JavaMail session and connect to server. - Modified to only allow connection to gmail server
		Store store = null;

		userName = dialog.getUsername();
		passWord = dialog.getPassword();
		Properties props = System.getProperties();

		props.put("mail.smtp.host", "smtp.gmail.com");
		props.put("mail.smtp.socketFactory.port", "465");
		props.put("mail.smtp.socketFactory.class",
				"javax.net.ssl.SSLSocketFactory");
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.port", "465");

		try {
			// Initialize JavaMail session with SMTP server.

			session = Session.getDefaultInstance(props,
					new javax.mail.Authenticator() {
						protected PasswordAuthentication getPasswordAuthentication() {
							return new PasswordAuthentication(userName,
									passWord);
						}
					});

			store = session.getStore("imaps");
			store.connect("imap.gmail.com", userName, passWord);

		} catch (Exception e) {
			System.out.print("Arse");
			// Close the downloading dialog.
			downloadingDialog.dispose();

			// Show error dialog.
			showError("Unable to connect.", true);
		}

		// Download message headers from server.
		try {
			// Open main "INBOX" folder.
			Folder folder = store.getFolder("INBOX");
			folder.open(Folder.READ_WRITE);

			// Get folder's list of messages.
			Message[] messages = folder.getMessages();

			// Retrieve message headers for each message in folder.
			FetchProfile profile = new FetchProfile();
			profile.add(FetchProfile.Item.ENVELOPE);
			folder.fetch(messages, profile);

			// Put messages in table.
			tableModel.setMessages(messages);
		} catch (Exception e) {
			// Close the downloading dialog.
			downloadingDialog.dispose();

			// Show error dialog.
			showError("Unable to download messages.", true);
		}

		// Close the downloading dialog.
		downloadingDialog.dispose();
	}

	public void actionRefresh() {
		// Download message headers from server.
		try {
			Store store = session.getStore("imaps");
			store.connect("imap.gmail.com", userName, passWord);
			// Open main "INBOX" folder.
			Folder folder = store.getFolder("INBOX");
			folder.open(Folder.READ_WRITE);

			// Get folder's list of messages.
			Message[] messages = folder.getMessages();

			// Retrieve message headers for each message in folder.
			FetchProfile profile = new FetchProfile();
			profile.add(FetchProfile.Item.ENVELOPE);
			folder.fetch(messages, profile);

			// Put messages in table.
			tableModel.setMessages(messages);
		} catch (Exception e) {
			// Show error dialog.
			showError("Unable to download messages.", true);
		}

	}

	// Show error dialog and exit afterwards if necessary.
	private void showError(String message, boolean exit) {
		JOptionPane.showMessageDialog(this, message, "Error",
				JOptionPane.ERROR_MESSAGE);
		if (exit)
			System.exit(0);
	}

	// Get a message's content.
	public static String getMessageContent(Message message) throws Exception {
		Object content = message.getContent();
		if (content instanceof Multipart) {
			StringBuffer messageContent = new StringBuffer();
			Multipart multipart = (Multipart) content;
			for (int i = 0; i < multipart.getCount(); i++) {
				Part part = (Part) multipart.getBodyPart(i);
				if (part.isMimeType("text/plain")) {
					messageContent.append(part.getContent().toString());
				}
			}
			return messageContent.toString();
		} else {
			return content.toString();
		}
	}

	// Run the E-mail Client.
	public static void main(String[] args) {
		EmailClient client = new EmailClient();
		client.show();

		// Display connect dialog.
		client.connect();
	}
}
