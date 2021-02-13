namespace NSeal
{
    using System.IO;

    /// <summary>
    /// Defines the encryption content description
    /// </summary>
    public struct EncryptionContent
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionContent"/> struct.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="content"></param>
        public EncryptionContent(string key, Stream content)
        {
            Key = key;
            Content = content;
        }

        /// <summary>
        /// Gets the key identifying the content.
        /// </summary>
        public string Key { get; }

        /// <summary>
        /// Gets the <see cref="Stream"/> holding the content.
        /// </summary>
        public Stream Content { get; }
    }
}
