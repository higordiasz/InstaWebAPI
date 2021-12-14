namespace InstaWebAPI.Response
{
    public class InstaResponse
    {
        public int Satus { get; set; }
        public string Response { get; set; }
    }

    public class InstaResponseJson
    {
        public int Status { get; set; }
        public string Response { get; set; }
        public dynamic Json { get; set; }
    }

    public class FriendshipRelation
    {
        public bool Is_Complet { get; set; }
        public bool Is_Private { get; set; }
        public bool Is_Followed { get; set; }
        public bool Is_Following { get; set; }
        public string PK { get; set; }
        public string Response { get; set; }
        public int Status { get; set; }
    }

    public class MediaRelation
    {
        public bool Is_Complet { get; set; }
        public bool Is_Liked { get; set; }
        public string MediaID { get; set; }
        public string MediaShortcode { get; set; }
        public string OwnerUsername { get; set; }
        public string OwnerPK { get; set; }
        public bool Is_FollowingOwner { get; set; }
        public bool Is_PrivateOwner { get; set; }
        public string Response { get; set; }
        public int Status { get; set; }
    }
}