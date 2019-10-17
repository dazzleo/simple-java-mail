package org.simplejavamail.internal.modules;

import org.simplejavamail.MailException;
import org.simplejavamail.api.email.Email;

import javax.mail.internet.MimeMessage;

/**
 * This interface only serves to hide the DKIM implementation behind an easy-to-load-with-reflection class.
 */
public interface DKIMModule {

	String NAME = "DKIM module";

	/**
	 * Primes the {@link MimeMessage} instance for signing with DKIM. The signing itself is performed by {@link net.markenwerk.utils.mail.dkim.DkimMessage} and {@link
	 * net.markenwerk.utils.mail.dkim.DkimSigner} during the physical sending of the message.
	 *
	 * @param messageToSign                 The message to be signed when sent.
	 * @param emailContainingSigningDetails The {@link Email} that contains the relevant signing information
	 *
	 * @return The original mime message wrapped in a new one that performs signing when sent.
	 * @throws MailException see:
	 *                       <ol>
	 *                           <li>{@code DkimSigner#DkimSigner(String, String, File)}</li>
	 *                           <li>{@code DkimSigner#DkimSigner(String, String, InputStream)}</li>
	 *                           <li>{@code DkimMessage#DkimMessage(MimeMessage, DkimSigner)} </li>
	 *                       </ol>
	 */
	MimeMessage signMessageWithDKIM(MimeMessage messageToSign, Email emailContainingSigningDetails)
			throws MailException;
}