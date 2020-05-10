namespace NSeal
{
    using System.IO;

    public struct EncryptionContent
    {
        public EncryptionContent(string key, Stream content)
        {
            Key = key;
            Content = content;
        }

        public string Key { get; }

        public Stream Content { get; }
    }
}
